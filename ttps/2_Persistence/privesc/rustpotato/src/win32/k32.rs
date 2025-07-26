use core::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{resolve_functions, win32::ldr::ldr_module};

use winapi::ctypes::c_void;

pub type PeekNamedPipe = unsafe extern "system" fn(
    hNamedPipe: *mut c_void,
    lpBuffer: *mut c_void,
    nBufferSize: u32,
    lpBytesRead: *mut u32,
    lpTotalBytesAvail: *mut u32,
    lpBytesLeftThisMessage: *mut u32,
) -> i32;

pub struct Kernel32 {
    pub module_base: *mut u8,
    pub peek_named_pipe: PeekNamedPipe,
}

impl Kernel32 {
    pub fn new() -> Self {
        Kernel32 {
            module_base: null_mut(),
            peek_named_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Kernel32 {}
unsafe impl Send for Kernel32 {}

static INIT_K32: AtomicBool = AtomicBool::new(false);

static mut K32_PTR: *const Kernel32 = core::ptr::null();

pub fn k32() -> &'static Kernel32 {
    unsafe { ensure_initialized() };
    unsafe { &*K32_PTR }
}

unsafe fn ensure_initialized() {
    // Check and call initialize if not already done.
    if !INIT_K32.load(Ordering::Acquire) {
        init_kernel32_funcs();
    }
}

pub fn init_kernel32_funcs() {
    unsafe {
        if !INIT_K32.load(Ordering::Acquire) {
            let mut k32 = Kernel32::new();

            k32.module_base = ldr_module(0x6ddb9555, None); // Kernel32.dll

            resolve_functions!(k32.module_base, [(
                k32.peek_named_pipe,
                0xd5312e5d,
                PeekNamedPipe
            )]);

            K32_PTR = Box::into_raw(Box::new(k32));

            INIT_K32.store(true, Ordering::Release);
        }
    }
}
