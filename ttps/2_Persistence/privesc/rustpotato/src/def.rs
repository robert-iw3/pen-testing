use core::ffi::c_void;

pub const BAD_HANDLE: *mut winapi::ctypes::c_void = -1isize as *mut winapi::ctypes::c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcServerInterface {
    pub length: u32,
    pub interface_id: RpcSyntaxIdentifier,
    pub transfer_syntax: RpcSyntaxIdentifier,
    pub dispatch_table: *mut RpcDispatchTable,
    pub rpc_protseq_endpoint_count: u32,
    pub rpc_protseq_endpoint: *mut RpcProtseqEndpoint,
    pub default_manager_epv: *mut core::ffi::c_void,
    pub interpreter_info: *const core::ffi::c_void,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcVersion {
    pub major_version: u16,
    pub minor_version: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcSyntaxIdentifier {
    pub syntax_guid: windows_core::GUID,
    pub syntax_version: RpcVersion,
}

pub type RpcDispatchFunction = Option<unsafe extern "system" fn(message: *mut RpcMessage)>;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcMessage {
    pub handle: *mut core::ffi::c_void,
    pub data_representation: u32,
    pub buffer: *mut core::ffi::c_void,
    pub buffer_length: u32,
    pub proc_num: u32,
    pub transfer_syntax: *mut RpcSyntaxIdentifier,
    pub rpc_interface_information: *mut core::ffi::c_void,
    pub reserved_for_runtime: *mut core::ffi::c_void,
    pub manager_epv: *mut core::ffi::c_void,
    pub import_context: *mut core::ffi::c_void,
    pub rpc_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RpcDispatchTable {
    pub dispatch_table_count: u32,
    pub dispatch_table: RpcDispatchFunction,
    pub reserved: isize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcProtseqEndpoint {
    pub rpc_protocol_sequence: *mut u8,
    pub endpoint: *mut u8,
}

#[repr(C)]
pub struct MidlServerInfo {
    pub p_stub_desc: *mut c_void,
    pub dispatch_table: *const c_void,
    pub proc_string: *mut u8,
    pub fmt_string_offset: *const u16,
    pub thunk_table: *const c_void,
    pub p_transfer_syntax: *mut c_void,
    pub n_count: usize,
    pub p_syntax_info: *mut c_void,
}

use windows_core::implement;

/// A fake COM object that implements the `IUnknown` interface.
#[implement()]
pub struct SampleCOMObject;

/// Represents various protocols used in DCOM communication.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TowerProtocol {
    EpmProtocolDnetNsp = 0x04,
    EpmProtocolOsiTp4 = 0x05,
    EpmProtocolOsiClns = 0x06,
    EpmProtocolTcp = 0x07,
    EpmProtocolUdp = 0x08,
    EpmProtocolIp = 0x09,
    EpmProtocolNcadg = 0x0a,
    EpmProtocolNcacn = 0x0b,
    EpmProtocolNcalrpc = 0x0c,
    EpmProtocolUuid = 0x0d,
    EpmProtocolIpx = 0x0e,
    EpmProtocolSmb = 0x0f,
    EpmProtocolNamedPipe = 0x10,
    EpmProtocolNetbios = 0x11,
    EpmProtocolNetbeui = 0x12,
    EpmProtocolSpx = 0x13,
    EpmProtocolNbIpx = 0x14,
    EpmProtocolDsp = 0x16,
    EpmProtocolDdp = 0x17,
    EpmProtocolAppletalk = 0x18,
    EpmProtocolVinesSpp = 0x1a,
    EpmProtocolVinesIpc = 0x1b,
    EpmProtocolStreettalk = 0x1c,
    EpmProtocolHttp = 0x1f,
    EpmProtocolUnixDs = 0x20,
    EpmProtocolNull = 0x21,
}

impl TryFrom<u16> for TowerProtocol {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x04 => Ok(TowerProtocol::EpmProtocolDnetNsp),
            0x05 => Ok(TowerProtocol::EpmProtocolOsiTp4),
            0x06 => Ok(TowerProtocol::EpmProtocolOsiClns),
            0x07 => Ok(TowerProtocol::EpmProtocolTcp),
            0x08 => Ok(TowerProtocol::EpmProtocolUdp),
            0x09 => Ok(TowerProtocol::EpmProtocolIp),
            0x0a => Ok(TowerProtocol::EpmProtocolNcadg),
            0x0b => Ok(TowerProtocol::EpmProtocolNcacn),
            0x0c => Ok(TowerProtocol::EpmProtocolNcalrpc),
            0x0d => Ok(TowerProtocol::EpmProtocolUuid),
            0x0e => Ok(TowerProtocol::EpmProtocolIpx),
            0x0f => Ok(TowerProtocol::EpmProtocolSmb),
            0x10 => Ok(TowerProtocol::EpmProtocolNamedPipe),
            0x11 => Ok(TowerProtocol::EpmProtocolNetbios),
            0x12 => Ok(TowerProtocol::EpmProtocolNetbeui),
            0x13 => Ok(TowerProtocol::EpmProtocolSpx),
            0x14 => Ok(TowerProtocol::EpmProtocolNbIpx),
            0x16 => Ok(TowerProtocol::EpmProtocolDsp),
            0x17 => Ok(TowerProtocol::EpmProtocolDdp),
            0x18 => Ok(TowerProtocol::EpmProtocolAppletalk),
            0x1a => Ok(TowerProtocol::EpmProtocolVinesSpp),
            0x1b => Ok(TowerProtocol::EpmProtocolVinesIpc),
            0x1c => Ok(TowerProtocol::EpmProtocolStreettalk),
            0x1f => Ok(TowerProtocol::EpmProtocolHttp),
            0x20 => Ok(TowerProtocol::EpmProtocolUnixDs),
            0x21 => Ok(TowerProtocol::EpmProtocolNull),
            _ => Err("Invalid TowerProtocol value"),
        }
    }
}
