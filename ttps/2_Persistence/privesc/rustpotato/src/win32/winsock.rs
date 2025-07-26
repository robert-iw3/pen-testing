use winapi::ctypes::c_void;

use core::{
    mem::zeroed,
    ptr::{null, null_mut},
};
use std::{
    ffi::CString,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    resolve_functions,
    win32::{def::UnicodeString, ntdll::ntdll},
};

pub const FIONBIO: i32 = -2147195266i32;

#[allow(non_camel_case_types)]
pub type SOCKET = usize;

// Data structures for Winsock
#[repr(C)]
pub struct WsaData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub sz_description: [i8; 257],
    pub sz_system_status: [i8; 129],
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: *mut i8,
}

#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [i8; 8],
}

#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
pub struct AddrInfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: u32,
    pub ai_canonname: *mut i8,
    pub ai_addr: *mut SockAddr,
    pub ai_next: *mut AddrInfo,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FD_SET {
    pub fd_count: u32,
    pub fd_array: [SOCKET; 64],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TIMEVAL {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

// Define function types for Winsock functions
type WSAStartupFunc =
    unsafe extern "system" fn(wVersionRequested: u16, lpWsaData: *mut WsaData) -> i32;
type WSACleanupFunc = unsafe extern "system" fn() -> i32;
type SocketFunc = unsafe extern "system" fn(af: i32, socket_type: i32, protocol: i32) -> SOCKET;
type ConnectFunc = unsafe extern "system" fn(s: SOCKET, name: *const SockAddr, namelen: i32) -> i32;
type SendFunc = unsafe extern "system" fn(s: SOCKET, buf: *const i8, len: i32, flags: i32) -> i32;
type RecvFunc = unsafe extern "system" fn(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32;
type CloseSocketFunc = unsafe extern "system" fn(s: SOCKET) -> i32;
type InetAddrFunc = unsafe extern "system" fn(cp: *const i8) -> u32;
type HtonsFunc = unsafe extern "system" fn(hostshort: u16) -> u16;
type GetAddrInfoFunc = unsafe extern "system" fn(
    node: *const i8,
    service: *const i8,
    hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> i32;
type FreeAddrInfoFunc = unsafe extern "system" fn(res: *mut AddrInfo);

type IoctlsocketFunc = unsafe extern "system" fn(s: SOCKET, cmd: i32, argp: *mut u32) -> i32;

type SelectFunc = unsafe extern "system" fn(
    nfds: i32,
    readfds: *mut FD_SET,
    writefds: *mut FD_SET,
    exceptfds: *mut FD_SET,
    timeout: *mut TIMEVAL,
) -> i32;

type WSAGetLastErrorFunc = unsafe extern "system" fn() -> i32;

pub struct Winsock {
    pub wsa_startup: WSAStartupFunc,
    pub wsa_cleanup: WSACleanupFunc,
    pub socket: SocketFunc,
    pub connect: ConnectFunc,
    pub send: SendFunc,
    pub recv: RecvFunc,
    pub closesocket: CloseSocketFunc,
    pub inet_addr: InetAddrFunc,
    pub htons: HtonsFunc,
    pub getaddrinfo: GetAddrInfoFunc,
    pub freeaddrinfo: FreeAddrInfoFunc,
    pub ioctlsocket: IoctlsocketFunc,
    pub select: SelectFunc,
    pub wsa_get_last_error: WSAGetLastErrorFunc,
}

impl Winsock {
    pub fn new() -> Self {
        Winsock {
            wsa_startup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_cleanup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            socket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            connect: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            send: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            recv: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            closesocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            inet_addr: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            htons: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            getaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            freeaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            ioctlsocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            select: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_get_last_error: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
        }
    }
}

static INIT_WS32: AtomicBool = AtomicBool::new(false);

static mut WS32_PTR: *const Winsock = core::ptr::null();

pub fn winsock() -> &'static Winsock {
    ensure_initialized();
    unsafe { &*WS32_PTR }
}

fn ensure_initialized() {
    // Check and call initialize if not already done.
    if !INIT_WS32.load(Ordering::Acquire) {
        init_winsock_funcs();
    }
}

pub fn init_winsock_funcs() {
    unsafe {
        if !INIT_WS32.load(Ordering::Acquire) {
            let mut winsock = Winsock::new();
            let dll_name = "ws2_32.dll";
            let mut ws2_win32_dll_unicode = UnicodeString::new();
            let utf16_string: Vec<u16> = dll_name.encode_utf16().chain(Some(0)).collect();
            ws2_win32_dll_unicode.init(utf16_string.as_ptr());

            let mut ws2_win32_handle: *mut c_void = null_mut();

            (ntdll().ldr_load_dll)(
                null_mut(),
                null_mut(),
                ws2_win32_dll_unicode,
                &mut ws2_win32_handle as *mut _ as *mut c_void,
            );

            if ws2_win32_handle.is_null() {
                return;
            }

            let ws2_32_module = ws2_win32_handle as *mut u8;

            resolve_functions!(ws2_32_module, [
                (winsock.wsa_startup, 0x142e89c3, WSAStartupFunc),
                (winsock.wsa_cleanup, 0x32206eb8, WSACleanupFunc),
                (winsock.socket, 0xcf36c66e, SocketFunc),
                (winsock.connect, 0xe73478ef, ConnectFunc),
                (winsock.send, 0x7c8bc2cf, SendFunc),
                (winsock.recv, 0x7c8b3515, RecvFunc),
                (winsock.closesocket, 0x185953a4, CloseSocketFunc),
                (winsock.inet_addr, 0xafe73c2f, InetAddrFunc),
                (winsock.htons, 0xd454eb1, HtonsFunc),
                (winsock.getaddrinfo, 0x4b91706c, GetAddrInfoFunc),
                (winsock.freeaddrinfo, 0x307204e, FreeAddrInfoFunc),
                (winsock.ioctlsocket, 0xd5e978a9, IoctlsocketFunc),
                (winsock.select, 0xce86a705, SelectFunc),
                (winsock.wsa_get_last_error, 0x9c1d912e, WSAGetLastErrorFunc)
            ]);

            WS32_PTR = Box::into_raw(Box::new(winsock));

            INIT_WS32.store(true, Ordering::Release);
        }
    }
}

/// Initializes the Winsock library for network operations on Windows.
/// Returns 0 on success, or the error code on failure.
pub fn init_winsock() -> i32 {
    unsafe {
        let mut wsa_data: WsaData = core::mem::zeroed();
        let result = (winsock().wsa_startup)(0x0202, &mut wsa_data);
        if result != 0 {
            return (winsock().wsa_get_last_error)();
        }
        result
    }
}

/// Creates a new TCP socket for network communication.
/// Returns the socket descriptor (SOCKET) or an error code on failure.
pub fn create_socket() -> SOCKET {
    unsafe {
        (winsock().socket)(2, 1, 6) // AF_INET, SOCK_STREAM, IPPROTO_TCP
    }
}

/// Resolves a hostname to an IPv4 address.
/// Returns the IPv4 address as a `u32` or an error code on failure.
pub fn resolve_hostname(hostname: &str) -> u32 {
    unsafe {
        let hostname_cstr = CString::new(hostname).unwrap();
        let mut hints: AddrInfo = zeroed();
        hints.ai_family = 2; // AF_INET
        hints.ai_socktype = 1; // SOCK_STREAM
        let mut res: *mut AddrInfo = null_mut();

        let status = (winsock().getaddrinfo)(hostname_cstr.as_ptr(), null(), &hints, &mut res);

        if status != 0 {
            return (winsock().wsa_get_last_error)() as u32;
        }

        let mut ip_addr: u32 = 0;
        let mut addr_info_ptr = res;

        while !addr_info_ptr.is_null() {
            let addr_info = &*addr_info_ptr;
            if addr_info.ai_family == 2 {
                // AF_INET
                let sockaddr_in = &*(addr_info.ai_addr as *const SockAddrIn);
                ip_addr = sockaddr_in.sin_addr.s_addr;
                break;
            }
            addr_info_ptr = addr_info.ai_next;
        }

        (winsock().freeaddrinfo)(res);
        ip_addr
    }
}

/// Connects a socket to a given address and port.
/// Returns 0 on success, or the error code on failure.
pub fn connect_socket(sock: SOCKET, addr: &str, port: u16) -> i32 {
    unsafe {
        let addr = if addr == "localhost" {
            "127.0.0.1"
        } else {
            addr
        };

        let resolve_addr = resolve_hostname(addr);
        let mut sockaddr_in: SockAddrIn = core::mem::zeroed();
        sockaddr_in.sin_family = 2; // AF_INET
        sockaddr_in.sin_port = (winsock().htons)(port);
        sockaddr_in.sin_addr.s_addr = resolve_addr;

        let sockaddr = &sockaddr_in as *const _ as *const SockAddr;
        let result = (winsock().connect)(sock, sockaddr, core::mem::size_of::<SockAddrIn>() as i32);

        if result != 0 {
            return (winsock().wsa_get_last_error)();
        }
        result
    }
}
