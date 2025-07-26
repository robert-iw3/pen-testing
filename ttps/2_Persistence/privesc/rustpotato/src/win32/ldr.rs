use winapi::ctypes::c_void;

use crate::{
    win32::def::{
        IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, ImageDosHeader, ImageExportDirectory,
        ImageNtHeaders, LoaderDataTableEntry, PebLoaderData, find_peb,
    },
    win32::utils::{dbj2_hash, get_cstr_len},
};

use core::ptr::null_mut;

use super::def::nt_current_teb;

/// Retrieves a handle to the process heap.
///
/// This function returns a handle to the heap used by the process, which is stored in the Process Environment Block (PEB).
/// It mimics the behavior of the `NtProcessHeap` macro in C.
pub fn nt_process_heap() -> *mut c_void {
    unsafe {
        nt_current_teb()
            .as_ref()
            .unwrap()
            .process_environment_block
            .as_ref()
            .unwrap()
            .process_heap
    }
}

/// Retrieves the NT headers from the base address of a module.
///
/// # Arguments
/// * `base_addr` - The base address of the module.
///
/// Returns a pointer to `ImageNtHeaders` or null if the headers are invalid.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn get_nt_headers(base_addr: *mut u8) -> *mut ImageNtHeaders {
    let dos_header = base_addr as *mut ImageDosHeader;

    // Check if the DOS signature is valid (MZ)
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    // Calculate the address of NT headers
    let nt_headers = (base_addr as isize + (*dos_header).e_lfanew as isize) as *mut ImageNtHeaders;

    // Check if the NT signature is valid (PE\0\0)
    if (*nt_headers).signature != IMAGE_NT_SIGNATURE as _ {
        return null_mut();
    }

    nt_headers
}

/// Locates a module by its hashed name, returning its base address and optionally populating its size.
///
/// # Arguments
/// * `module_hash` - The hash of the module name to locate.
/// * `size` - An optional mutable reference to store the size of the module in memory.
///
/// # Returns
/// The base address of the module, or `null` if the module is not found.
///
/// # Notes
/// - If the module is found and `size` is provided, it is populated with the module's size.
/// - Returns `null_mut()` if the module is not found.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn ldr_module(module_hash: u32, out_module_size: Option<&mut usize>) -> *mut u8 {
    let peb = find_peb(); // Retrieve the PEB (Process Environment Block)

    if peb.is_null() {
        return null_mut();
    }

    let peb_ldr_data_ptr = (*peb).loader_data as *mut PebLoaderData;
    if peb_ldr_data_ptr.is_null() {
        return null_mut();
    }

    // Start with the first module in the InLoadOrderModuleList
    let mut module_list =
        (*peb_ldr_data_ptr).in_load_order_module_list.flink as *mut LoaderDataTableEntry;

    // Iterate through the list of loaded modules
    while !(*module_list).dll_base.is_null() {
        let dll_buffer_ptr = (*module_list).base_dll_name.buffer;
        let dll_length = (*module_list).base_dll_name.length as usize;

        // Create a slice from the DLL name
        let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        // Compare the hash of the DLL name with the provided hash
        if module_hash == dbj2_hash(dll_name_slice) {
            if let Some(size_ref) = out_module_size {
                *size_ref = (*module_list).size_of_image as usize; // Set the size if provided
            }
            return (*module_list).dll_base as _; // Return the base address of the module if the hash matches
        }

        // Move to the next module in the list
        module_list = (*module_list).in_load_order_links.flink as *mut LoaderDataTableEntry;
    }

    null_mut() // Return null if no matching module is found
}

/// Finds a function by its hash from the export directory of a module.
///
/// # Arguments
/// * `module_base` - The base address of the module.
/// * `function_hash` - The hash of the function name to locate.
///
/// Returns the function's address or null if not found.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn ldr_function(module_base: *mut u8, function_hash: usize) -> *mut u8 {
    let p_img_nt_headers = get_nt_headers(module_base); // Retrieve NT headers for the module

    if p_img_nt_headers.is_null() {
        return null_mut();
    }

    // Get the export directory from the NT headers
    let data_directory = &(*p_img_nt_headers).optional_header.data_directory[0];
    let export_directory =
        (module_base.offset(data_directory.virtual_address as isize)) as *mut ImageExportDirectory;
    if export_directory.is_null() {
        return null_mut();
    }

    let number_of_functions = (*export_directory).number_of_functions;
    let array_of_names =
        module_base.offset((*export_directory).address_of_names as isize) as *const u32;
    let array_of_addresses =
        module_base.offset((*export_directory).address_of_functions as isize) as *const u32;
    let array_of_ordinals =
        module_base.offset((*export_directory).address_of_name_ordinals as isize) as *const u16;

    // Create slices from the export directory arrays
    let names = core::slice::from_raw_parts(array_of_names, number_of_functions as _);
    let functions = core::slice::from_raw_parts(array_of_addresses, number_of_functions as _);
    let ordinals = core::slice::from_raw_parts(array_of_ordinals, number_of_functions as _);

    // Iterate through the export names to find the function matching the given hash
    for i in 0..number_of_functions {
        let name_addr = module_base.offset(names[i as usize] as isize) as *const i8;
        let name_len = get_cstr_len(name_addr as _); // Get the length of the function name
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        // Compare the hash of the function name with the provided hash
        if function_hash as u32 == dbj2_hash(name_slice) {
            // Retrieve the function's address by its ordinal
            let ordinal = ordinals[i as usize] as usize;
            return module_base.offset(functions[ordinal] as isize) as *mut u8;
        }
    }

    null_mut() // Return null if the function is not found
}
