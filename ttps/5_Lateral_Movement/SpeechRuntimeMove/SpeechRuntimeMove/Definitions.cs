using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace SpeechRuntimeMove
{
    public  class Definitions
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct COAUTHINFO
        {
            public uint dwAuthnSvc;
            public uint dwAuthzSvc;
            public IntPtr pwszServerPrincName;
            public uint dwAuthnLevel;
            public uint dwImpersonationLevel;
            public IntPtr pAuthIdentityData;
            public uint dwCapabilities;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct COAUTHIDENTITY
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;
            [MarshalAs(UnmanagedType.U4)]
            public uint UserLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;
            [MarshalAs(UnmanagedType.U4)]
            public uint DomainLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Password;
            [MarshalAs(UnmanagedType.U4)]
            public uint PasswordLength;
            public uint Flags;
        }


        [ComImport(), Guid("884CCD87-B139-4937-A4BA-4F8E19513FBE"),
InterfaceTypeAttribute(ComInterfaceType.InterfaceIsIUnknown)
]
        public interface ISyncMgrSyncCallback
        {
        }

        [ComImport, Guid("17F48517-F305-4321-A08D-B25A834918FD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface SyncMgrSessionCreator
        {
            [PreserveSig]
            int CreateSession([In, MarshalAs(UnmanagedType.LPWStr)] string pszHandlerID,
             [In, MarshalAs(UnmanagedType.LPWStr)] ref string ppszItemIDs,
             [In] uint cItems,
             [MarshalAs(UnmanagedType.Interface)] out ISyncMgrSyncCallback ppCallback);
        }

        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            IntPtr asAuthSvc,
            IntPtr pReserved1,
            int dwAuthnLevel,
            int dwImpLevel,
            IntPtr pAuthList,
            int dwCapabilities,
            IntPtr pReserved3);

        [DllImport("ole32.dll")]
        public static extern int CoCreateInstanceEx(in Guid rclsid, IntPtr punkOuter, SpeechRuntimeMove.Definitions.CLSCTX dwClsCtx, IntPtr pServerInfo, int dwCount, [In, Out] SpeechRuntimeMove.Definitions.MULTI_QI[] pResults);


        public const int RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        public const int RPC_C_IMP_LEVEL_IMPERSONATE = 3;
        public const int RPC_C_AUTHN_WINNT = 10;
        public const int RPC_C_AUTHZ_NONE = 0;
        public const int EOAC_NONE = 0;


        public static void InitAuthStructs(ref COAUTHINFO authInfo)
        {
            authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
            authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
            authInfo.pwszServerPrincName = IntPtr.Zero;
            authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
            authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
            authInfo.dwCapabilities = EOAC_NONE;
            authInfo.pAuthIdentityData = IntPtr.Zero; // Use current user's credentials
        }

        [DllImport("ole32.Dll")]
        public static extern uint CoCreateInstance(ref Guid clsid,
           [MarshalAs(UnmanagedType.IUnknown)] object inner,
           uint context,
           ref Guid uuid,
           [MarshalAs(UnmanagedType.IUnknown)] out object rReturnedComObject);

        [DllImport("ole32.dll", PreserveSig = false, ExactSpelling = true)]
        public static extern int CreateILockBytesOnHGlobal(
         IntPtr hGlobal,
         [MarshalAs(UnmanagedType.Bool)] bool fDeleteOnRelease,
         out ILockBytes ppLkbyt);

        [DllImport("ole32.dll", PreserveSig = false, ExactSpelling = true)]
        public static extern int StgCreateDocfileOnILockBytes(
           ILockBytes plkbyt,
           STGM grfMode,
           uint reserved,
           out IStorage ppstgOpen);

        [DllImport("ole32.dll")]
        public static extern int CreateObjrefMoniker(
        IntPtr punk,
        out IMoniker ppmk);

        [DllImport("ole32.dll")]
        public static extern int CreateBindCtx(
              int reserved,
              out IBindCtx ppbc
            );

        [DllImport("ole32.dll")]
        public static extern void CoUninitialize();

        [DllImport("rpcrt4.dll")]
        public static extern int RpcServerUseProtseqEp(
    string Protseq,
    uint MaxCalls,
    string Endpoint,
    IntPtr SecurityDescriptor);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcServerRegisterAuthInfo", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RpcServerRegisterAuthInfo(String ServerPrincName, uint AuthnSvc, IntPtr GetKeyFn, IntPtr Arg);

        public static byte[] GetMarshalledObject(object o)
        {
            IMoniker mk;

            CreateObjrefMoniker(Marshal.GetIUnknownForObject(o), out mk);

            IBindCtx bc;

            CreateBindCtx(0, out bc);

            string name;

            mk.GetDisplayName(bc, null, out name);

            return Convert.FromBase64String(name.Substring(7).TrimEnd(':'));
        }

        [ComImport]
        [Guid("0000000d-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IEnumSTATSTG
        {
            // The user needs to allocate an STATSTG array whose size is celt.
            [PreserveSig]
            uint
            Next(uint celt, [MarshalAs(UnmanagedType.LPArray), Out] System.Runtime.InteropServices.ComTypes.STATSTG[] rgelt, out uint pceltFetched);

            void Skip(uint celt);

            void Reset();

            [return: MarshalAs(UnmanagedType.Interface)]
            IEnumSTATSTG Clone();
        }

        [ComVisible(false)]
        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000A-0000-0000-C000-000000000046")]
        public interface ILockBytes
        {
            //Note: These two by(reference 32-bit integers (ULONG) could be used as return values instead,
            //      but they are not tagged [retval] in the IDL, so for consitency's sake...
            void ReadAt(long ulOffset, System.IntPtr pv, int cb, out System.UInt32 pcbRead);

            void WriteAt(long ulOffset, System.IntPtr pv, int cb, out System.UInt32 pcbWritten);

            void Flush();

            void SetSize(long cb);

            void LockRegion(long libOffset, long cb, int dwLockType);

            void UnlockRegion(long libOffset, long cb, int dwLockType);

            void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG[] pstatstg, int grfStatFlag);
        }

        [Guid("00000003-0000-0000-C000-000000000046")]
        [InterfaceType(1)]
        [ComConversionLoss]
        [ComImport]
        public interface IMarshal
        {
            void GetUnmarshalClass([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out Guid pCid);

            void GetMarshalSizeMax([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out uint pSize);

            void MarshalInterface([MarshalAs(28)][In] IStream pstm, [In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS);

            void UnmarshalInterface([MarshalAs(28)][In] IStream pstm, [In] ref Guid riid, out IntPtr ppv);

            void ReleaseMarshalData([MarshalAs(28)][In] IStream pstm);

            void DisconnectObject([In] uint dwReserved);
        }

        [InterfaceType(1)]
        [ComConversionLoss]
        [Guid("0000000B-0000-0000-C000-000000000046")]
        [ComImport]
        public interface IStorage
        {
            void CreateStream([MarshalAs(21)][In] string pwcsName, [In] uint grfMode, [In] uint reserved1, [In] uint reserved2, [MarshalAs(28)] out IStream ppstm);

            void OpenStream([MarshalAs(21)][In] string pwcsName, [In] IntPtr reserved1, [In] uint grfMode, [In] uint reserved2, [MarshalAs(28)] out IStream ppstm);

            void CreateStorage([MarshalAs(21)][In] string pwcsName, [In] uint grfMode, [In] uint reserved1, [In] uint reserved2, [MarshalAs(28)] out IStorage ppstg);

            void OpenStorage([MarshalAs(21)][In] string pwcsName, [MarshalAs(28)][In] IStorage pstgPriority, [In] uint grfMode, [In] IntPtr snbExclude, [In] uint reserved, [MarshalAs(28)] out IStorage ppstg);

            void CopyTo([In] uint ciidExclude, [MarshalAs(42, SizeParamIndex = 0)][In] Guid[] rgiidExclude, [In] IntPtr snbExclude, [MarshalAs(28)][In] IStorage pstgDest);

            void MoveElementTo([MarshalAs(21)][In] string pwcsName, [MarshalAs(28)][In] IStorage pstgDest, [MarshalAs(21)][In] string pwcsNewName, [In] uint grfFlags);

            void Commit([In] uint grfCommitFlags);

            void Revert();

            void EnumElements([In] uint reserved1, [In] IntPtr reserved2, [In] uint reserved3, [MarshalAs(28)] out IEnumSTATSTG ppEnum);

            void DestroyElement([MarshalAs(21)][In] string pwcsName);

            void RenameElement([MarshalAs(21)][In] string pwcsOldName, [MarshalAs(21)][In] string pwcsNewName);

            void SetElementTimes([MarshalAs(21)][In] string pwcsName, [MarshalAs(42)][In] System.Runtime.InteropServices.ComTypes.FILETIME[] pctime, [MarshalAs(42)][In] System.Runtime.InteropServices.ComTypes.FILETIME[] patime, [MarshalAs(42)][In] System.Runtime.InteropServices.ComTypes.FILETIME[] pmtime);

            void SetClass([In] ref Guid clsid);

            void SetStateBits([In] uint grfStateBits, [In] uint grfMask);

            void Stat([MarshalAs(42)][Out] System.Runtime.InteropServices.ComTypes.STATSTG[] pstatstg, [In] uint grfStatFlag);
        }

        [ComImport, Guid("0000000c-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IStream
        {
            void Read([Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, uint cb, out uint pcbRead);

            void Write([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, uint cb, out uint pcbWritten);

            void Seek(long dlibMove, uint dwOrigin, out long plibNewPosition);

            void SetSize(long libNewSize);

            void CopyTo(IStream pstm, long cb, out long pcbRead, out long pcbWritten);

            void Commit(uint grfCommitFlags);

            void Revert();

            void LockRegion(long libOffset, long cb, uint dwLockType);

            void UnlockRegion(long libOffset, long cb, uint dwLockType);

            void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg, uint grfStatFlag);

            void Clone(out IStream ppstm);
        }

        [Flags]
        public enum CLSCTX : uint
        {
            CLSCTX_INPROC_SERVER = 0x1,
            CLSCTX_INPROC_HANDLER = 0x2,
            CLSCTX_LOCAL_SERVER = 0x4,
            CLSCTX_INPROC_SERVER16 = 0x8,
            CLSCTX_REMOTE_SERVER = 0x10,
            CLSCTX_INPROC_HANDLER16 = 0x20,
            CLSCTX_RESERVED1 = 0x40,
            CLSCTX_RESERVED2 = 0x80,
            CLSCTX_RESERVED3 = 0x100,
            CLSCTX_RESERVED4 = 0x200,
            CLSCTX_NO_CODE_DOWNLOAD = 0x400,
            CLSCTX_RESERVED5 = 0x800,
            CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
            CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
            CLSCTX_NO_FAILURE_LOG = 0x4000,
            CLSCTX_DISABLE_AAA = 0x8000,
            CLSCTX_ENABLE_AAA = 0x10000,
            CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
            CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000,
            CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000,
            CLSCTX_INPROC = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
            CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
            CLSCTX_ALL = CLSCTX_SERVER | CLSCTX_INPROC_HANDLER
        }

        [Flags]
        public enum STGM : int
        {
            DIRECT = 0x00000000,
            TRANSACTED = 0x00010000,
            SIMPLE = 0x08000000,
            READ = 0x00000000,
            WRITE = 0x00000001,
            READWRITE = 0x00000002,
            SHARE_DENY_NONE = 0x00000040,
            SHARE_DENY_READ = 0x00000030,
            SHARE_DENY_WRITE = 0x00000020,
            SHARE_EXCLUSIVE = 0x00000010,
            PRIORITY = 0x00040000,
            DELETEONRELEASE = 0x04000000,
            NOSCRATCH = 0x00100000,
            CREATE = 0x00001000,
            CONVERT = 0x00020000,
            FAILIFTHERE = 0x00000000,
            NOSNAPSHOT = 0x00200000,
            DIRECT_SWMR = 0x00400000,
        }

        public static IntPtr GuidToPointer(Guid g)
        {
            IntPtr ret = Marshal.AllocCoTaskMem(16);
            Marshal.Copy(g.ToByteArray(), 0, ret, 16);
            return ret;
        }

        public static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");
        public static IntPtr IID_IUnknownPtr = GuidToPointer(IID_IUnknown);

        [StructLayout(LayoutKind.Sequential)]
        public struct MULTI_QI
        {
            public IntPtr pIID;

            [MarshalAs(UnmanagedType.Interface)]
            public object pItf;

            public int hr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class COSERVERINFO
        {
            public uint dwReserved1;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;

            public IntPtr pAuthInfo;
            public uint dwReserved2;
        }

        [Guid("0000033C-0000-0000-c000-000000000046")]
        [ComImport]
        public class StandardActivator
        {
        }

        internal enum RUNLEVEL : uint
        {
            RUNLEVEL_LUA = 0x0,
            RUNLEVEL_HIGHEST = 0x1,
            RUNLEVEL_ADMIN = 0x2,
            RUNLEVEL_MAX_NON_UIA = 0x3,
            RUNLEVEL_LUA_UIA = 0x10,
            RUNLEVEL_HIGHEST_UIA = 0x11,
            RUNLEVEL_ADMIN_UIA = 0x12,
            RUNLEVEL_MAX = 0x13,
            INVALID_LUA_RUNLEVEL = 0xFFFFFFFF,
        };

        internal enum PRT
        {
            PRT_IGNORE = 0x0,
            PRT_CREATE_NEW = 0x1,
            PRT_USE_THIS = 0x2,
            PRT_USE_THIS_ONLY = 0x3,
        };

        [Guid("000001B9-0000-0000-c000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface ISpecialSystemPropertiesActivator
        {
            void SetSessionId(int dwSessionId, int bUseConsole, int fRemoteThisSessionId);

            void GetSessionId(out int pdwSessionId, out int pbUseConsole);

            void GetSessionId2(out int pdwSessionId, out int pbUseConsole, out int pfRemoteThisSessionId);

            void SetClientImpersonating(int fClientImpersonating);

            void GetClientImpersonating(out int pfClientImpersonating);

            void SetPartitionId(ref Guid guidPartition);

            void GetPartitionId(out Guid pguidPartition);

            void SetProcessRequestType(PRT dwPRT);

            void GetProcessRequestType(out PRT pdwPRT);

            void SetOrigClsctx(int dwOrigClsctx);

            void GetOrigClsctx(out int pdwOrigClsctx);

            void GetDefaultAuthenticationLevel(out int pdwDefaultAuthnLvl);

            void SetDefaultAuthenticationLevel(int dwDefaultAuthnLvl);

            void GetLUARunLevel(out RUNLEVEL pdwLUARunLevel, out IntPtr phwnd);

            void SetLUARunLevel(RUNLEVEL dwLUARunLevel, IntPtr hwnd);
        }

        [Guid("000001B8-0000-0000-c000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IStandardActivator
        {
            void StandardGetClassObject(in Guid rclsid, CLSCTX dwContext, [In] COSERVERINFO pServerInfo, in Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppvClassObj);

            void StandardCreateInstance(in Guid Clsid, IntPtr punkOuter, CLSCTX dwClsCtx, [In] COSERVERINFO pServerInfo, int dwCount, [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

            void StandardGetInstanceFromFile([In] COSERVERINFO pServerInfo, in Guid pclsidOverride,
                IntPtr punkOuter, CLSCTX dwClsCtx, int grfMode, [MarshalAs(UnmanagedType.LPWStr)] string pwszName, int dwCount, [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

            int StandardGetInstanceFromIStorage(
                [In] COSERVERINFO pServerInfo,
                in Guid pclsidOverride,
                IntPtr punkOuter,
                CLSCTX dwClsCtx,
                IStorage pstg,
                int dwCount,
                [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

            int StandardGetInstanceFromIStoragee(
                COSERVERINFO pServerInfo,
                ref Guid pclsidOverride,
                [MarshalAs(UnmanagedType.IUnknown)] object pUnkOuter,
                CLSCTX dwClsCtx,
                IStorage pstg,
                int dwCount,
                [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

            void Reset();
        }

        public enum TowerProtocol : ushort
        {
            EPM_PROTOCOL_DNET_NSP = 0x04,
            EPM_PROTOCOL_OSI_TP4 = 0x05,
            EPM_PROTOCOL_OSI_CLNS = 0x06,
            EPM_PROTOCOL_TCP = 0x07,
            EPM_PROTOCOL_UDP = 0x08,
            EPM_PROTOCOL_IP = 0x09,
            EPM_PROTOCOL_NCADG = 0x0a, /* Connectionless RPC */
            EPM_PROTOCOL_NCACN = 0x0b,
            EPM_PROTOCOL_NCALRPC = 0x0c, /* Local RPC */
            EPM_PROTOCOL_UUID = 0x0d,
            EPM_PROTOCOL_IPX = 0x0e,
            EPM_PROTOCOL_SMB = 0x0f,
            EPM_PROTOCOL_NAMED_PIPE = 0x10,
            EPM_PROTOCOL_NETBIOS = 0x11,
            EPM_PROTOCOL_NETBEUI = 0x12,
            EPM_PROTOCOL_SPX = 0x13,
            EPM_PROTOCOL_NB_IPX = 0x14, /* NetBIOS over IPX */
            EPM_PROTOCOL_DSP = 0x16, /* AppleTalk Data Stream Protocol */
            EPM_PROTOCOL_DDP = 0x17, /* AppleTalk Data Datagram Protocol */
            EPM_PROTOCOL_APPLETALK = 0x18, /* AppleTalk */
            EPM_PROTOCOL_VINES_SPP = 0x1a,
            EPM_PROTOCOL_VINES_IPC = 0x1b, /* Inter Process Communication */
            EPM_PROTOCOL_STREETTALK = 0x1c, /* Vines Streettalk */
            EPM_PROTOCOL_HTTP = 0x1f,
            EPM_PROTOCOL_UNIX_DS = 0x20, /* Unix domain socket */
            EPM_PROTOCOL_NULL = 0x21
        }

        [ComVisible(true)]
        public class StorageTrigger : IMarshal, IStorage
        {
            private IStorage storage;
            private string binding;
            private TowerProtocol towerProtocol;
            private object SobjRef;

            public StorageTrigger(IStorage storage, string binding, TowerProtocol towerProtocol, object SobjRef = null)
            {
                this.storage = storage;
                this.binding = binding;
                this.towerProtocol = towerProtocol;
                this.SobjRef = SobjRef;
            }

            public void DisconnectObject(uint dwReserved)
            {
            }

            public void GetMarshalSizeMax(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out uint pSize)
            {
                pSize = 1024;
            }

            public void GetUnmarshalClass(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out Guid pCid)
            {
                pCid = new Guid("00000306-0000-0000-c000-000000000046");
            }

            public void MarshalInterface(IStream pstm, ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS)
            {
                //ObjRef objRef = new ObjRef(Ole32.IID_IUnknown,
                //      new ObjRef.Standard(0x1000, 1, 0x0703d84a06ec96cc, 0x539d029cce31ac, new Guid("{042c939f-54cd-efd4-4bbd-1c3bae972145}"),
                //        new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0xa, 0xffff, null))));
                //
                //
                //byte[] data = new byte[] { };
                //if (SobjRef == null)
                //{
                //    data = objRef.GetBytes();
                //}
                //else
                //{
                //    //objRef = new ObjRef(Ole32.IID_IUnknown,
                //    //  new ObjRef.Standard((uint)((COMObjRefStandard)SobjRef).Flags, (uint)((COMObjRefStandard)SobjRef).PublicRefs, ((COMObjRefStandard)SobjRef).Oxid, ((COMObjRefStandard)SobjRef).Oid, ((COMObjRefStandard)SobjRef).Ipid,
                //    //    new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0x0010, 0xffff, "LDAP/ADMINIS-UB1IMGM.htb.local"))));
                //    //data = objRef.GetBytes();
                //    data = ((COMObjRefStandard)SobjRef).ToArray();
                //}
                uint written;
                var data = ((COMObjRefStandard)SobjRef).ToArray();
                pstm.Write(data, (uint)data.Length, out written);
            }

            public void ReleaseMarshalData(IStream pstm)
            {
            }

            public void UnmarshalInterface(IStream pstm, ref Guid riid, out IntPtr ppv)
            {
                ppv = IntPtr.Zero;
            }

            public void Commit(uint grfCommitFlags)
            {
                storage.Commit(grfCommitFlags);
            }

            public void CopyTo(uint ciidExclude, Guid[] rgiidExclude, IntPtr snbExclude, IStorage pstgDest)
            {
                storage.CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
            }

            public void CreateStorage(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStorage ppstg)
            {
                storage.CreateStorage(pwcsName, grfMode, reserved1, reserved2, out ppstg);
            }

            public void CreateStream(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStream ppstm)
            {
                storage.CreateStream(pwcsName, grfMode, reserved1, reserved2, out ppstm);
            }

            public void DestroyElement(string pwcsName)
            {
                storage.DestroyElement(pwcsName);
            }

            public void EnumElements(uint reserved1, IntPtr reserved2, uint reserved3, out IEnumSTATSTG ppEnum)
            {
                storage.EnumElements(reserved1, reserved2, reserved3, out ppEnum);
            }

            public void MoveElementTo(string pwcsName, IStorage pstgDest, string pwcsNewName, uint grfFlags)
            {
                storage.MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
            }

            public void OpenStorage(string pwcsName, IStorage pstgPriority, uint grfMode, IntPtr snbExclude, uint reserved, out IStorage ppstg)
            {
                storage.OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, out ppstg);
            }

            public void OpenStream(string pwcsName, IntPtr reserved1, uint grfMode, uint reserved2, out IStream ppstm)
            {
                storage.OpenStream(pwcsName, reserved1, grfMode, reserved2, out ppstm);
            }

            public void RenameElement(string pwcsOldName, string pwcsNewName)
            {
            }

            public void Revert()
            {
            }

            public void SetClass(ref Guid clsid)
            {
            }

            public void SetElementTimes(string pwcsName, System.Runtime.InteropServices.ComTypes.FILETIME[] pctime, System.Runtime.InteropServices.ComTypes.FILETIME[] patime, System.Runtime.InteropServices.ComTypes.FILETIME[] pmtime)
            {
            }

            public void SetStateBits(uint grfStateBits, uint grfMask)
            {
            }

            public void Stat(System.Runtime.InteropServices.ComTypes.STATSTG[] pstatstg, uint grfStatFlag)
            {
                storage.Stat(pstatstg, grfStatFlag);
                pstatstg[0].pwcsName = "hello.stg";
            }
        }

        [Flags]
        public enum COMObjrefFlags
        {
            None = 0,
            Standard = 1,
            Handler = 2,
            Custom = 4,
            Extended = 8,
        }

        public enum RpcAuthnService : short
        {
            None = 0,
            DCEPrivate = 1,
            DCEPublic = 2,
            DECPublic = 4,
            GSS_Negotiate = 9,
            WinNT = 10,
            GSS_SChannel = 14,
            GSS_Kerberos = 16,
            DPA = 17,
            MSN = 18,
            Digest = 21,
            Kernel = 20,
            NegoExtender = 30,
            PKU2U = 31,
            LiveSSP = 32,
            LiveXPSSP = 35,
            MSOnline = 82,
            MQ = 100,
            Default = -1,
        }

        // Note that most of these won't actually work.
        public enum RpcTowerId : short
        {
            None = 0,
            DNetNSP = 0x04, // ncacn_dnet_dsp
            Tcp = 0x07,     // ncacg_ip_tcp
            Udp = 0x08,     // ncacn_ip_udp
            NetbiosTcp = 0x09, // ncacn_nb_tcp
            Spx = 0x0C,         // ncacn_spx
            NetbiosIpx = 0xD,   // ncacn_np_ipx
            Ipx = 0x0E,         // ncacg_ipx
            NamedPipe = 0xF,    // ncacn_np
            LRPC = 0x10,        // ncalrpc
            NetBIOS = 0x13,     // ncacn_nb_nb
            AppleTalkDSP = 0x16,// ncacn_at_dsp
            AppleTalkDDP = 0x17,// ncacg_at_ddp
            BanyanVinesSPP = 0x1A, // ncacn_vns_spp
            MessageQueue = 0x1D,   // ncadg_mq
            Http = 0x1F,           // ncacn_http
            Container = 0x21,      // ncacn_hvsocket
            StringBinding = -1,
        }

        public class COMStringBinding
        {
            public RpcTowerId TowerId { get; set; }
            public string NetworkAddr { get; set; }

            public COMStringBinding() : this(0, string.Empty)
            {
            }

            public COMStringBinding(RpcTowerId tower_id, string network_addr)
            {
                TowerId = tower_id;
                NetworkAddr = network_addr;
            }

            internal COMStringBinding(BinaryReader reader, bool direct_string)
            {
                if (direct_string)
                {
                    try
                    {
                        TowerId = RpcTowerId.StringBinding;
                        NetworkAddr = reader.ReadZString();
                    }
                    catch (EndOfStreamException)
                    {
                        NetworkAddr = string.Empty;
                    }
                }
                else
                {
                    TowerId = (RpcTowerId)reader.ReadInt16();
                    if (TowerId != RpcTowerId.None)
                    {
                        NetworkAddr = reader.ReadZString();
                    }
                    else
                    {
                        NetworkAddr = string.Empty;
                    }
                }
            }

            public void ToWriter(BinaryWriter writer)
            {
                writer.Write((short)TowerId);
                if (TowerId != 0)
                {
                    writer.WriteZString(NetworkAddr);
                }
            }

            public override string ToString()
            {
                return $"TowerId: {TowerId} - NetworkAddr: {NetworkAddr}";
            }

            internal COMStringBinding Clone()
            {
                return (COMStringBinding)MemberwiseClone();
            }
        }

        public class COMSecurityBinding
        {
            public RpcAuthnService AuthnSvc { get; set; }
            public string PrincName { get; set; }

            public COMSecurityBinding() : this(0, string.Empty)
            {
            }

            public COMSecurityBinding(RpcAuthnService authn_svc, string princ_name)
            {
                AuthnSvc = authn_svc;
                PrincName = princ_name;
            }

            internal COMSecurityBinding(BinaryReader reader)
            {
                AuthnSvc = (RpcAuthnService)reader.ReadInt16();
                if (AuthnSvc != 0)
                {
                    // Reserved
                    reader.ReadInt16();
                    PrincName = reader.ReadZString();
                }
                else
                {
                    PrincName = string.Empty;
                }
            }

            public void ToWriter(BinaryWriter writer)
            {
                writer.Write((short)AuthnSvc);
                if (AuthnSvc != 0)
                {
                    writer.Write((ushort)0xFFFF);
                    writer.WriteZString(PrincName);
                }
            }

            public override string ToString()
            {
                return $"AuthnSvc: {AuthnSvc} - PrincName: {PrincName}";
            }

            internal COMSecurityBinding Clone()
            {
                return (COMSecurityBinding)MemberwiseClone();
            }
        }

        internal class COMDualStringArray
        {
            public List<COMStringBinding> StringBindings { get; private set; }
            public List<COMSecurityBinding> SecurityBindings { get; private set; }

            public COMDualStringArray()
            {
                StringBindings = new List<COMStringBinding>();
                SecurityBindings = new List<COMSecurityBinding>();
            }

            private void ReadEntries(BinaryReader new_reader, int sec_offset, bool direct_string)
            {
                COMStringBinding str = new COMStringBinding(new_reader, direct_string);
                if (direct_string)
                {
                    StringBindings.Add(str);
                }
                else
                {
                    while (str.TowerId != 0)
                    {
                        StringBindings.Add(str);
                        str = new COMStringBinding(new_reader, direct_string);
                    }
                }

                new_reader.BaseStream.Position = sec_offset * 2;
                COMSecurityBinding sec = new COMSecurityBinding(new_reader);
                while (sec.AuthnSvc != 0)
                {
                    SecurityBindings.Add(sec);
                    sec = new COMSecurityBinding(new_reader);
                }
            }

            //public COMDualStringArray(IntPtr ptr, NtProcess process, bool direct_string) : this()
            //{
            //    int num_entries = process.ReadMemory<ushort>(ptr.ToInt64());
            //    int sec_offset = process.ReadMemory<ushort>(ptr.ToInt64() + 2);
            //    if (num_entries > 0)
            //    {
            //        MemoryStream stm = new MemoryStream(process.ReadMemory(ptr.ToInt64() + 4, num_entries * 2));
            //        ReadEntries(new BinaryReader(stm), sec_offset, direct_string);
            //    }
            //}

            internal COMDualStringArray(BinaryReader reader) : this()
            {
                int num_entries = reader.ReadUInt16();
                int sec_offset = reader.ReadUInt16();

                if (num_entries > 0)
                {
                    MemoryStream stm = new MemoryStream(reader.ReadAll(num_entries * 2));
                    BinaryReader new_reader = new BinaryReader(stm);
                    ReadEntries(new_reader, sec_offset, false);
                }
            }

            public void ToWriter(BinaryWriter writer)
            {
                MemoryStream stm = new MemoryStream();
                BinaryWriter new_writer = new BinaryWriter(stm);
                if (StringBindings.Count > 0)
                {
                    foreach (COMStringBinding str in StringBindings)
                    {
                        str.ToWriter(new_writer);
                    }
                    new COMStringBinding().ToWriter(new_writer);
                }
                ushort ofs = (ushort)(stm.Position / 2);
                if (SecurityBindings.Count > 0)
                {
                    foreach (COMSecurityBinding sec in SecurityBindings)
                    {
                        sec.ToWriter(new_writer);
                    }
                    new COMSecurityBinding().ToWriter(new_writer);
                }
                writer.Write((ushort)(stm.Length / 2));
                writer.Write(ofs);
                writer.Write(stm.ToArray());
            }

            internal COMDualStringArray Clone()
            {
                COMDualStringArray ret = new COMDualStringArray();
                ret.StringBindings.AddRange(StringBindings.Select(b => b.Clone()));
                ret.SecurityBindings.AddRange(SecurityBindings.Select(b => b.Clone()));
                return ret;
            }
        }

        public abstract class COMObjRef
        {
            public const int OBJREF_MAGIC = 0x574f454d;

            public Guid Iid { get; set; }

            public COMObjrefFlags Flags
            {
                get
                {
                    if (this is COMObjRefCustom)
                    {
                        return COMObjrefFlags.Custom;
                    }
                    else if (this is COMObjRefHandler)
                    {
                        return COMObjrefFlags.Handler;
                    }
                    else if (this is COMObjRefStandard)
                    {
                        return COMObjrefFlags.Standard;
                    }
                    else
                    {
                        return COMObjrefFlags.None;
                    }
                }
            }

            public byte[] ToArray()
            {
                MemoryStream stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stm);
                writer.Write(OBJREF_MAGIC);
                writer.Write((int)Flags);
                writer.Write(Iid);
                Serialize(writer);
                return stm.ToArray();
            }

            public string ToMoniker()
            {
                return $"objref:{Convert.ToBase64String(ToArray())}:";
            }

            protected abstract void Serialize(BinaryWriter writer);

            protected COMObjRef(Guid iid)
            {
                Iid = iid;
            }

            public static COMObjRef FromArray(byte[] arr)
            {
                MemoryStream stm = new MemoryStream(arr);
                BinaryReader reader = new BinaryReader(stm);
                int magic = reader.ReadInt32();
                if (magic != OBJREF_MAGIC)
                {
                    throw new ArgumentException("Invalid OBJREF Magic");
                }

                COMObjrefFlags flags = (COMObjrefFlags)reader.ReadInt32();
                Guid iid = reader.ReadGuid();
                switch (flags)
                {
                    case COMObjrefFlags.Custom:
                        return new COMObjRefCustom(reader, iid);

                    case COMObjrefFlags.Standard:
                        return new COMObjRefStandard(reader, iid);

                    case COMObjrefFlags.Handler:
                        return new COMObjRefHandler(reader, iid);

                    case COMObjrefFlags.Extended:
                    default:
                        throw new ArgumentException("Invalid OBJREF Type Flags");
                }
            }
        }

        public class COMObjRefCustom : COMObjRef
        {
            public Guid Clsid { get; set; }
            public int Reserved { get; set; }
            public byte[] ExtensionData { get; set; }
            public byte[] ObjectData { get; set; }

            //public COMObjRefCustom()
            //    : base(COMInterfaceEntry.IID_IUnknown)
            //{
            //    ObjectData = new byte[0];
            //    ExtensionData = new byte[0];
            //}

            internal COMObjRefCustom(BinaryReader reader, Guid iid)
                : base(iid)
            {
                Clsid = reader.ReadGuid();
                // Size of extension data but can be 0.
                int extension = reader.ReadInt32();
                ExtensionData = new byte[extension];
                Reserved = reader.ReadInt32();
                if (extension > 0)
                {
                    ExtensionData = reader.ReadAll(extension);
                }
                // Read to end of stream.
                ObjectData = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
            }

            protected override void Serialize(BinaryWriter writer)
            {
                writer.Write(Clsid);
                writer.Write(ExtensionData.Length);
                writer.Write(Reserved);
                writer.Write(ExtensionData);
                writer.Write(ObjectData);
            }
        }

        [Flags]
        public enum COMStdObjRefFlags
        {
            None = 0,
            NoPing = 0x1000
        }

        internal class COMStdObjRef
        {
            public COMStdObjRefFlags StdFlags { get; set; }
            public int PublicRefs { get; set; }
            public ulong Oxid { get; set; }
            public ulong Oid { get; set; }
            public Guid Ipid { get; set; }

            public COMStdObjRef()
            {
            }

            internal COMStdObjRef(BinaryReader reader)
            {
                StdFlags = (COMStdObjRefFlags)reader.ReadInt32();
                PublicRefs = reader.ReadInt32();
                Oxid = reader.ReadUInt64();
                Oid = reader.ReadUInt64();
                Ipid = reader.ReadGuid();
            }

            public void ToWriter(BinaryWriter writer)
            {
                writer.Write((int)StdFlags);
                writer.Write(PublicRefs);
                writer.Write(Oxid);
                writer.Write(Oid);
                writer.Write(Ipid);
            }

            internal COMStdObjRef Clone()
            {
                return (COMStdObjRef)MemberwiseClone();
            }
        }

        public class COMObjRefStandard : COMObjRef
        {
            internal COMStdObjRef _stdobjref;
            internal COMDualStringArray _stringarray;

            public COMStdObjRefFlags StdFlags { get => _stdobjref.StdFlags; set => _stdobjref.StdFlags = value; }
            public int PublicRefs { get => _stdobjref.PublicRefs; set => _stdobjref.PublicRefs = value; }
            public ulong Oxid { get => _stdobjref.Oxid; set => _stdobjref.Oxid = value; }
            public ulong Oid { get => _stdobjref.Oid; set => _stdobjref.Oid = value; }
            public Guid Ipid { get => _stdobjref.Ipid; set => _stdobjref.Ipid = value; }

            public List<COMStringBinding> StringBindings => _stringarray.StringBindings;
            public List<COMSecurityBinding> SecurityBindings => _stringarray.SecurityBindings;

            public int ProcessId => COMUtilities.GetProcessIdFromIPid(Ipid);

            public string ProcessName => COMUtilities.GetProcessNameById(ProcessId);

            public int ApartmentId => COMUtilities.GetApartmentIdFromIPid(Ipid);
            public string ApartmentName => COMUtilities.GetApartmentIdStringFromIPid(Ipid);

            internal COMObjRefStandard(BinaryReader reader, Guid iid)
                : base(iid)
            {
                _stdobjref = new COMStdObjRef(reader);
                _stringarray = new COMDualStringArray(reader);
            }

            protected COMObjRefStandard(Guid iid) : base(iid)
            {
            }

            protected COMObjRefStandard(COMObjRefStandard std) : base(std.Iid)
            {
                _stdobjref = std._stdobjref.Clone();
                _stringarray = std._stringarray.Clone();
            }

            public COMObjRefStandard() : base(Guid.Empty)
            {
                _stdobjref = new COMStdObjRef();
                _stringarray = new COMDualStringArray();
            }

            protected override void Serialize(BinaryWriter writer)
            {
                _stdobjref.ToWriter(writer);
                _stringarray.ToWriter(writer);
            }

            public COMObjRefHandler ToHandler(Guid clsid)
            {
                return new COMObjRefHandler(clsid, this);
            }
        }

        public class COMObjRefHandler : COMObjRefStandard
        {
            public Guid Clsid { get; set; }

            internal COMObjRefHandler(BinaryReader reader, Guid iid)
                : base(iid)
            {
                _stdobjref = new COMStdObjRef(reader);
                Clsid = reader.ReadGuid();
                _stringarray = new COMDualStringArray(reader);
            }

            internal COMObjRefHandler(Guid clsid, COMObjRefStandard std) : base(std)
            {
                Clsid = clsid;
            }

            public COMObjRefHandler() : base()
            {
            }

            protected override void Serialize(BinaryWriter writer)
            {
                _stdobjref.ToWriter(writer);
                writer.Write(Clsid);
                _stringarray.ToWriter(writer);
            }
        }



    }
}
