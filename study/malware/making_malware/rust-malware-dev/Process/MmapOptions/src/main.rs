use memmap2::MmapOptions;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

fn load_shellcode<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut shellcode = Vec::new();

    file.read_to_end(&mut shellcode)?;

    Ok(shellcode)
}

fn execute_shellcode(shellcode: &[u8]) -> io::Result<()> {
    if shellcode.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shellcode is empty",
        ));
    }

    let shellcode_size = shellcode.len();

    let mut mmap = MmapOptions::new()
        .len(shellcode_size)
        .map_anon()
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to map memory: {}", e))
        })?;

    mmap.copy_from_slice(shellcode);

    let mmap = mmap.make_exec().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to make executable: {}", e),
        )
    })?;

    if mmap.as_ptr().align_offset(std::mem::align_of::<usize>()) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Memory is not properly aligned",
        ));
    }

    // exec using fn !
    unsafe {
        let shell: unsafe extern "C" fn() = std::mem::transmute(mmap.as_ptr());
        shell();
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let shellcode_path = "msgbox_shellcode.bin";

    let shellcode = load_shellcode(shellcode_path)?;
    println!("[+] Loading shellcode ({} bytes)", shellcode.len());

    println!("[+] Executing shellcode...");
    execute_shellcode(&shellcode)?;

    println!("[+] Shellcode executed successfully");
    Ok(())
}
