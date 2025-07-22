use winapi::ctypes::c_void;
use winapi::um::winbase::{CreateNamedPipeA, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_READMODE_MESSAGE, PIPE_WAIT};
use winapi::um::winnt::LPCSTR;
use winapi::um::namedpipeapi::{ConnectNamedPipe, DisconnectNamedPipe};
use winapi::um::fileapi::{WriteFile, FlushFileBuffers};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use std::ptr::null_mut;

fn main() {
    let pipe_name: LPCSTR = "\\\\.\\pipe\\maldevmsg\0".as_ptr() as *const i8;
    let message = "Hey 5mukx is here. Pwn it, Nail it.\0";


    loop{
        let server_pipe: *mut c_void = unsafe{
            CreateNamedPipeA(
                pipe_name,
                PIPE_ACCESS_DUPLEX,                // Read/write access
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // Message mode, blocking
                1,                               // Max instances
                2048,                           // Out buffer size
                2048,                            // In buffer size
                0,                             // Default timeout
                null_mut(),               // No security attributes
            )
        };

        if server_pipe.is_null() || server_pipe == INVALID_HANDLE_VALUE{
            eprintln!("Failed to create pipe: {}", std::io::Error::last_os_error());
            return;
        }

        println!("Waiting for client to connect... ");
        
        let connected = unsafe { 
            ConnectNamedPipe(server_pipe, null_mut()) 
        };

        if connected == 0 && std::io::Error::last_os_error().raw_os_error() != Some(0){
            eprintln!("Failed to connect: {}", std::io::Error::last_os_error());
            unsafe{ CloseHandle(server_pipe)}; 
            return;
        }

        println!("Client Connected! Sending message ...!");

        let mut bytes_written: u32 = 0;
        let success = unsafe {
            WriteFile(
                server_pipe,
                message.as_ptr() as *const c_void,
                message.len() as u32,
                &mut bytes_written,
                null_mut(),
            )
        };


        if success == 0 {
            eprintln!("Failed to write to pipe: {}", std::io::Error::last_os_error());
        } else {
            println!("Sent: {}", message.trim_end_matches('\0'));
        }

        unsafe { FlushFileBuffers(server_pipe) };
        unsafe { DisconnectNamedPipe(server_pipe) };
        unsafe { CloseHandle(server_pipe) };
    }

}
