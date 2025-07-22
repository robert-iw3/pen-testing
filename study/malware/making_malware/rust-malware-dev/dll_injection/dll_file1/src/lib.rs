use std::ffi::CString;
use std::ptr::{null, null_mut};
use winapi::shared::minwindef::{BOOL, DWORD, HMODULE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::FreeLibraryAndExitThread;
use winapi::um::processthreadsapi::{
    CreateProcessA, CreateThread, PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_NEW_CONSOLE, INFINITE};
use winapi::um::winnt::PVOID;

struct ThreadData {
    h_process: PVOID,
    h_thread: PVOID,
    h_module: HMODULE,
}

extern "system" fn thread_proc(lp_param: PVOID) -> DWORD {
    let data = lp_param as *mut ThreadData;
    let process_info = unsafe {&*data};
    unsafe {
        WaitForSingleObject(process_info.h_process, INFINITE);
        CloseHandle(process_info.h_process);
        CloseHandle(process_info.h_thread);
        FreeLibraryAndExitThread(process_info.h_module, 0);
    }
    0 // This line won't actually be reached due to FreeLibraryAndExitThread
}

#[unsafe(no_mangle)]
pub extern "stdcall" fn DllMain(
    h_module: HMODULE,
    dw_reason: DWORD,
    _lp_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match dw_reason {
        1 => {
            // DLL_PROCESS_ATTACH
            unsafe {
                let mut startup_info: STARTUPINFOA = std::mem::zeroed();
                startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

                let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

                let application_name = match CString::new("C:\\Windows\\System32\\calc.exe") {
                    Ok(cstr) => cstr,
                    Err(_) => return 0,
                };

                let success = CreateProcessA(
                    null(),
                    application_name.as_ptr() as *mut i8,
                    null_mut(),
                    null_mut(),
                    0,
                    CREATE_NEW_CONSOLE,
                    null_mut(),
                    null(),
                    &mut startup_info,
                    &mut process_info,
                );

                if success == 0 {
                    return 0;
                }
            
                // create thread data !
                let thread_data = Box::into_raw(Box::new(ThreadData {
                    h_process: process_info.hProcess,
                    h_thread: process_info.hThread,
                    h_module,
                }));


                let thread_handle = CreateThread(
                    null_mut(),
                    0,                    
                    Some(thread_proc),   
                    thread_data as PVOID, 
                    0,                   
                    null_mut(),          
                );

                if thread_handle.is_null() {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                    let _ = Box::from_raw(thread_data);
                    return 0;
                }

                CloseHandle(thread_handle);
                1
            }
        }
        0 => 1, // DLL_PROCESS_DETACH
        _ => 1,
    }
}
