use crate::win32::{
    def::{
        ImageDosHeader, ImageExportDirectory, ImageNtHeaders, ListEntry, LoaderDataTableEntry,
        PebLoaderData, find_peb,
    },
    utils::{dbj2_hash, get_cstr_len},
};

/// Retrieves the System Service Number (SSN) and the address for a specified syscall.
///
/// This function scans the loaded modules in memory to locate `ntdll.dll`, then utilizes the Exception Directory and
/// Export Address Table to identify the specified syscall. It matches the syscall by hash
/// and returns the SSN if a match is found. Additionally, the function updates the `addr` parameter with the function’s address in `ntdll.dll`.
///
/// For more details on this approach, see MDsec's article on using the Exception Directory to resolve System Service Numbers:
/// https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/
///
/// # Parameters
/// - `hash`: The hash value of the syscall to locate.
/// - `addr`: A mutable reference that will be updated with the address of the matched function in `ntdll.dll`.
///
/// # Returns
/// - The SSN (System Service Number) of the specified syscall if a match is found.
/// - `-1` if no match is found. In this case, the `addr` parameter remains unchanged.
pub fn get_ssn(hash: usize, addr: &mut *mut u8) -> i32 {
    let peb = find_peb(); // Get the Process Environment Block (PEB)
    let ldr = unsafe { (*peb).loader_data as *mut PebLoaderData };

    // Traverse the list of loaded modules in memory.
    let mut next = unsafe { (*ldr).in_memory_order_module_list.flink };
    let head = &mut unsafe { (*ldr).in_memory_order_module_list };

    while next != head {
        let ent = unsafe { (next as *mut u8).offset(-(core::mem::size_of::<ListEntry>() as isize)) }
            as *mut LoaderDataTableEntry;
        next = unsafe { (*ent).in_memory_order_links.flink };

        let dll_base = unsafe { (*ent).dll_base as *const u8 };
        let dos_header = dll_base as *const ImageDosHeader;
        let nt_headers =
            unsafe { dll_base.offset((*dos_header).e_lfanew as isize) } as *const ImageNtHeaders;

        let export_directory_rva =
            unsafe { (*nt_headers).optional_header.data_directory[0].virtual_address };
        if export_directory_rva == 0 {
            continue;
        }

        let export_directory = unsafe { dll_base.offset(export_directory_rva as isize) }
            as *const ImageExportDirectory;

        if unsafe { (*export_directory).number_of_names == 0 } {
            continue;
        }

        let dll_name = unsafe { dll_base.offset((*export_directory).name as isize) } as *const u8;
        let dll_name_len = get_cstr_len(dll_name as _);
        let dll_name_str = unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(dll_name, dll_name_len))
        };

        // If module name is not ntdll.dll, skip.
        if dbj2_hash(dll_name_str.as_bytes()) != 0x1edab0ed {
            continue;
        }

        // Retrieve the Exception Directory.
        let rva = unsafe { (*nt_headers).optional_header.data_directory[3].virtual_address };
        if rva == 0 {
            // _print!("[-] RTF RVA is 0, returning -1...");
            return -1;
        }

        let rtf = (unsafe { dll_base.offset(rva as isize) }) as PimageRuntimeFunctionEntry;

        // Access the Export Address Table.
        let address_of_functions =
            unsafe { dll_base.offset((*export_directory).address_of_functions as isize) }
                as *const core::ffi::c_ulong;
        let address_of_names =
            unsafe { dll_base.offset((*export_directory).address_of_names as isize) }
                as *const core::ffi::c_ulong;
        let address_of_name_ordinals =
            unsafe { dll_base.offset((*export_directory).address_of_name_ordinals as isize) }
                as *const core::ffi::c_ushort;

        let mut ssn = 0; // Initialize the system call number (SSN).

        // Traverse the runtime function table.
        for i in 0.. {
            let begin_address = unsafe { (*rtf.offset(i as isize)).begin_address };
            if begin_address == 0 {
                break;
            }

            // Search the export address table.
            for j in 0..unsafe { (*export_directory).number_of_functions } {
                let ordinal = unsafe { *address_of_name_ordinals.offset(j as isize) };
                let function_address = unsafe { *address_of_functions.offset(ordinal as isize) };

                // Check if the function's address matches the runtime function's address.
                if function_address == begin_address {
                    let api_name_addr =
                        unsafe { dll_base.offset(*address_of_names.offset(j as isize) as isize) }
                            as *const u8;
                    let api_name_len = get_cstr_len(api_name_addr as _);
                    let api_name_str = unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                            api_name_addr,
                            api_name_len,
                        ))
                    };

                    // Match either by hash or by name.
                    if hash == dbj2_hash(api_name_str.as_bytes()) as usize {
                        *addr = unsafe { dll_base.offset(function_address as isize) } as *mut u8;
                        return ssn;
                    }

                    // Increment SSN if the function starts with "Zw" (system call).
                    if api_name_str.starts_with("Zw") {
                        ssn += 1;
                    }
                }
            }
        }
    }

    -1 // Return -1 if no syscall is found.
}

#[repr(C)]
pub struct ImageRuntimeFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub u: IMAGE_RUNTIME_FUNCTION_ENTRY_u,
}

#[repr(C)]
pub union IMAGE_RUNTIME_FUNCTION_ENTRY_u {
    pub unwind_info_address: u32,
    pub unwind_data: u32,
}

/// Type alias for pointer to `_IMAGE_RUNTIME_FUNCTION_ENTRY`
pub type PimageRuntimeFunctionEntry = *mut ImageRuntimeFunctionEntry;
