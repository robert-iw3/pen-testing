# Technical Writeup: version.dll Sideloading, Proxying, and Hooking

## Introduction

This document provides a detailed technical analysis of a proof-of-concept that demonstrates DLL sideloading by targeting `OneDrive.exe` with a malicious `version.dll`. This technique is leveraged for achieving persistence, evading defenses, and executing arbitrary code within the context of a trusted process. The proof-of-concept further employs DLL proxying to maintain the normal operation of the host application and utilizes a sophisticated hooking mechanism based on Vectored Exception Handling (VEH) and hardware-like breakpoints to intercept and modify application behavior.

## Core Concepts

### DLL Sideloading

DLL sideloading is a common attack vector where a legitimate application is tricked into loading a malicious DLL instead of the intended one. This is often possible due to the way Windows resolves DLL dependencies, following a specific search order. If an attacker can place a malicious DLL in a directory that is searched before the legitimate DLL's location, the malicious library will be loaded. This technique is particularly effective for defense evasion as the malicious code executes under the umbrella of a trusted, and often signed, executable.

In this proof-of-concept, `OneDrive.exe` is the target application, and `version.dll` is the sideloaded library. Many applications, including `OneDrive.exe`, have a dependency on `version.dll` for retrieving file version information. By placing a custom `version.dll` in the application's directory, we can hijack the loading process.

### DLL Proxying

Simply replacing a required DLL with a malicious one would likely cause the host application to crash if it cannot find the necessary functions (exports) it expects from that DLL. To circumvent this, DLL proxying is employed. The malicious DLL is crafted to export the same functions as the original, legitimate DLL. When the host application calls one of these functions, the proxy DLL can either execute its own malicious code, pass the call through to the original DLL, or both. This maintains the application's stability while allowing the malicious code to operate.

The `exports.h` file in this project demonstrates this technique. It uses `#pragma comment(linker, "/export:...")` directives to forward all the expected exports from the proxy `version.dll` to the legitimate `version.dll` located in `C:\Windows\System32\`. This ensures that any calls made by `OneDrive.exe` to functions within `version.dll` are correctly handled by the original library, preventing crashes and raising less suspicion.

### API Hooking with Vectored Exception Handling (VEH) and PAGE_GUARD

A key component of this proof-of-concept is its advanced method for API hooking. Instead of traditional methods like inline hooking, which can be detected by security products, this implementation uses a more covert technique involving Vectored Exception Handling (VEH) and memory page protection.

VEH is a mechanism in Windows that allows developers to register a function to be called whenever an exception occurs in a process. This proof-of-concept intentionally triggers exceptions to gain control of the execution flow.

The process is as follows:
1.  **Installation**: The `InstallHook` function in `hook.cpp` retrieves the address of the target function, `CreateWindowExW`, from `user32.dll`.
2.  **VEH Registration**: It then registers a custom exception handler, `VectoredHandler`, using `AddVectoredExceptionHandler`.
3.  **Triggering Exceptions**: The key to this technique is modifying the memory protection of the target function's first byte. `VirtualProtect` is used to add the `PAGE_GUARD` flag to the memory page containing `CreateWindowExW`. When the application attempts to execute this function, a `STATUS_GUARD_PAGE_VIOLATION` exception is raised.
4.  **Exception Handling**: The `VectoredHandler` catches this specific exception. It then redirects the instruction pointer (`Rip` in the context record) to our malicious function, `HookedCreateWindowExW`.
5.  **Re-arming the Hook**: After the exception is handled, the `PAGE_GUARD` is removed by the system. To ensure the hook remains active for subsequent calls, the handler also sets the single-step flag (`EFlags |= 0x100`). This causes a `STATUS_SINGLE_STEP` exception after the next instruction executes, which is also caught by our handler. Inside the single-step handler, the `PAGE_GUARD` is reapplied to the original function's memory page.

This method of hooking is stealthy because it doesn't directly modify the code of the hooked function in a persistent way, making it more difficult for security software to detect.

## Code Breakdown

### `dllmain.cpp`

This is the entry point of our malicious DLL. When the DLL is loaded into the `OneDrive.exe` process (`DLL_PROCESS_ATTACH`), it performs the following actions:
*   `DisableThreadLibraryCalls(hModule)`: An optimization to prevent the DLL from receiving thread-level attach and detach notifications, which are not needed in this case.
*   `InstallHook()`: Sets up the VEH-based hook on the `CreateWindowExW` function.
*   `CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL)`: Spawns a new thread to execute the main payload, ensuring that the DllMain function returns quickly and does not block the loader.

### `hook.cpp`

This file contains the logic for the API hooking:
*   `HookedCreateWindowExW`: This is our malicious replacement for the `CreateWindowExW` function. In this PoC, it simply removes the `WS_VISIBLE` style from any window being created, effectively making new windows invisible. This serves as a simple demonstration of modifying the application's behavior.
*   `VectoredHandler`: The core of the hooking mechanism. It handles the `STATUS_GUARD_PAGE_VIOLATION` and `STATUS_SINGLE_STEP` exceptions to redirect execution and re-arm the hook.
*   `InstallHook`: The setup function that finds the target function's address, registers the exception handler, and sets the initial `PAGE_GUARD`.

### `payload.cpp`

This file contains the primary malicious payload:
*   `PayloadThread`: This function is executed in a new thread. It waits for two seconds (`Sleep(2000)`) before executing its main logic.
*   `CreateProcessW`: The core of the payload. It uses the `CreateProcessW` function to launch a new process. In this case, it executes `"cmd.exe /c notepad.exe"`, which opens Notepad. The `CREATE_NO_WINDOW` flag is used to hide the `cmd.exe` window.
*   **Error Logging**: If `CreateProcessW` fails, the code writes the error code to a log file at `C:\Users\Public\log.txt` for debugging purposes.

## Execution Flow

1.  The malicious `version.dll` and a legitimate copy of `OneDrive.exe` are placed in the same directory.
2.  When `OneDrive.exe` is executed, the Windows loader searches for `version.dll` in the application's directory first, loading our malicious DLL.
3.  `DllMain` is called with `DLL_PROCESS_ATTACH`.
4.  The `InstallHook` function sets up the VEH hook on `CreateWindowExW`.
5.  A new thread is created, which executes `PayloadThread`.
6.  The `exports.h` pragmas ensure that any legitimate calls from `OneDrive.exe` to `version.dll` functions are forwarded to the original system DLL, allowing `OneDrive.exe` to run without crashing.
7.  After a two-second delay, the `PayloadThread` executes `CreateProcessW` to launch `notepad.exe`.
8.  If `OneDrive.exe` attempts to create a new window by calling `CreateWindowExW`, our hook intercepts the call and makes the window invisible.

## Conclusion

This proof-of-concept effectively demonstrates a multi-stage attack that combines DLL sideloading, DLL proxying, and advanced API hooking techniques. By targeting a trusted application like `OneDrive.exe`, an attacker can execute arbitrary code in a stealthy and persistent manner. The use of VEH-based hooking further enhances the evasiveness of this technique, making it a potent tool in an adversary's arsenal. Understanding the mechanics of such attacks is crucial for developing effective detection and mitigation strategies.
