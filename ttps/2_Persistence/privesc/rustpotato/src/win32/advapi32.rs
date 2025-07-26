use std::{
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{resolve_functions, win32::ldr::ldr_module};

use super::def::{ProcessInformation, StartupInfoW};

use winapi::ctypes::c_void;

pub type CreateProcessWithTokenW = unsafe extern "system" fn(
    hToken: *mut winapi::ctypes::c_void,
    dwLogonFlags: u32,
    lpApplicationName: *const u16,
    lpCommandLine: *mut u16,
    dwCreationFlags: u32,
    lpEnvironment: *mut c_void,
    lpCurrentDirectory: *const u16,
    lpStartupInfo: *mut StartupInfoW,
    lpProcessInformation: *mut ProcessInformation,
) -> i32;

pub struct Advapi32 {
    pub module_base: *mut u8,
    pub create_process_with_token_w: CreateProcessWithTokenW,
}

impl Advapi32 {
    pub fn new() -> Self {
        Advapi32 {
            module_base: null_mut(),
            create_process_with_token_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Advapi32 {}
unsafe impl Send for Advapi32 {}

/// Atomic flag to ensure initialization happens only once.
static INIT_ADVAPI32: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of advapi32.dll.
static mut ADVAPI32_PTR: *const Advapi32 = core::ptr::null();

/// Accessor for the `Advapi32` instance.
pub unsafe fn advapi32() -> &'static Advapi32 {
    unsafe { ensure_initialized_advapi32() };
    unsafe { &*ADVAPI32_PTR }
}

unsafe fn ensure_initialized_advapi32() {
    if !INIT_ADVAPI32.load(Ordering::Acquire) {
        init_advapi32_funcs();
    }
}

pub fn init_advapi32_funcs() {
    unsafe {
        if !INIT_ADVAPI32.load(Ordering::Acquire) {
            let mut advapi32 = Advapi32::new();

            advapi32.module_base = ldr_module(0x64bb3129, None); // advapi32.dll

            resolve_functions!(advapi32.module_base, [(
                advapi32.create_process_with_token_w,
                0xf3e5480c,
                CreateProcessWithTokenW
            )]);

            ADVAPI32_PTR = Box::into_raw(Box::new(advapi32));

            INIT_ADVAPI32.store(true, Ordering::Release);
        }
    }
}
