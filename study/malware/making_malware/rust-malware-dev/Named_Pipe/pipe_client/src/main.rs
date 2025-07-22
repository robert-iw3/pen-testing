use winapi::ctypes::c_void;
use winapi::um::fileapi::{CreateFileA, ReadFile};
use winapi::um::handleapi::CloseHandle;
use std::ptr::null_mut;


fn main() {
    let pipe_name: *const i8 = "\\\\.\\pipe\\maldevmsg\0".as_ptr() as *const i8;

    // connect with retries
    let client_pipe: *mut c_void = loop{
        let handle = unsafe{
            CreateFileA(
                pipe_name,
                0x80000000 | 0x40000000,
                0,              // No sharing
                null_mut(),     // Default security
                3,  // Open existing pipe
                0,              // Default attributes
                null_mut(),     // No template
            )
        };
        
        if handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            break handle;
        }

        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(231 /*ERROR_PIPE_BUSY*/ as i32) {
            println!("Pipe busy, retrying in 1 second...");
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }

        eprintln!("Failed to connect to pipe: {}", error);
        return;
    };

    println!("Connected to server!");

    let mut buffer = vec![0u8; 1024];
    let mut bytes_read: u32 = 0;
    let success = unsafe {
        ReadFile(
            client_pipe,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytes_read,
            null_mut(),
        )
    };

    if success == 0 {
        eprintln!("Failed to read from pipe: {}", std::io::Error::last_os_error());
    } else {
        let received = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        println!("Received: {}", received.trim_end_matches('\0'));
    }

    unsafe { 
        CloseHandle(client_pipe) 
    };
}


