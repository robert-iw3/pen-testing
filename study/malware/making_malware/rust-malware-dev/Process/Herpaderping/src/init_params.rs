use std::ptr::null_mut;

use ntapi::ntpebteb::PEB;
use ntapi::{
    ntmmapi::{NtAllocateVirtualMemory, NtReadVirtualMemory, NtWriteVirtualMemory},
    ntpsapi::{NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION},
    ntrtl::{
        RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
        RTL_USER_PROCESS_PARAMETERS, RTL_USER_PROC_PARAMS_NORMALIZED,
    },
};
use winapi::{
    ctypes::c_void,
    shared::ntdef::{NT_SUCCESS, UNICODE_STRING},
    um::userenv::CreateEnvironmentBlock,
};

pub fn init_params(
    h_process: *mut c_void,
    path_temp: String,
    dir_temp: String, /*,args: String */
) -> Result<*mut c_void, String> {
    // you can add arguments if you have to .. for example
    // let command_line = format!("{} {}", path_temp, args)
    let command_line = format!("{}", path_temp);
    let current_directory = dir_temp;
    let image_path = path_temp;

    let mut user_proc_params: PRTL_USER_PROCESS_PARAMETERS = unsafe { std::mem::zeroed() };
    let mut process_basic_information: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut peb: PEB = unsafe { std::mem::zeroed() };

    let mut enviroment = null_mut();
    unsafe { CreateEnvironmentBlock(&mut enviroment, null_mut(), 1) };

    let mut u_command_line: UNICODE_STRING = unsafe { std::mem::zeroed() };
    let mut u_current_directory: UNICODE_STRING = unsafe { std::mem::zeroed() };
    let mut u_image_path: UNICODE_STRING = unsafe { std::mem::zeroed() };

    unsafe {
        RtlInitUnicodeString(&mut u_command_line, command_line.as_ptr() as *const u16);
        RtlInitUnicodeString(
            &mut u_current_directory,
            current_directory.as_ptr() as *const u16,
        );
        RtlInitUnicodeString(&mut u_image_path, image_path.as_ptr() as *const u16);
    };

    let mut status = unsafe {
        RtlCreateProcessParametersEx(
            &mut user_proc_params,
            &mut u_image_path,
            null_mut(),
            &mut u_current_directory,
            &mut u_command_line,
            enviroment,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(format!(
            "[-] RtlCreateProcessParametersEx Failed With Status: {status}"
        ));
    }

    status = unsafe {
        NtQueryInformationProcess(
            h_process,
            ProcessBasicInformation,
            &mut process_basic_information as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };

    if !NT_SUCCESS(status) {
        return Err(format!(
            "[-] NtQueryInformationProcess Failed With Status: {status}"
        ));
    }

    status = unsafe {
        NtReadVirtualMemory(
            h_process,
            process_basic_information.PebBaseAddress as *mut c_void,
            &mut peb as *mut _ as *mut c_void,
            std::mem::size_of::<PEB>(),
            null_mut(),
        )
    };

    if !NT_SUCCESS(status) {
        return Err(format!(
            "[-] NtReadVirtualMemory Failed With Status: {status}"
        ));
    }

    println!(
        "[+] Address PEB: {:?}",
        process_basic_information.PebBaseAddress
    );

    let mut user_proc_base = user_proc_params as usize;
    let mut user_proc_end =
        unsafe { (user_proc_params as usize) + (*user_proc_params).Length as usize };
    unsafe {
        if !(*user_proc_params).Environment.is_null() {
            if user_proc_params as usize > (*user_proc_params).Environment as usize {
                user_proc_base = (*user_proc_params).Environment as usize;
            }

            if ((*user_proc_params).Environment as usize) + (*user_proc_params).EnvironmentSize
                > user_proc_end
            {
                user_proc_end = ((*user_proc_params).Environment as usize)
                    + (*user_proc_params).EnvironmentSize;
            }
        }
    }

    let mut size_param = user_proc_end - user_proc_base;
    let mut base_address = user_proc_params as *mut c_void;

    status = unsafe {
        NtAllocateVirtualMemory(
            h_process,
            &mut base_address,
            0,
            &mut size_param,
            0x1000 | 0x2000,
            0x40,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(format!(
            "[-] NtAllocateVirtualMemory Failed With Status: {status}"
        ));
    }

    let mut number_of_write = 0;
    status = unsafe {
        NtWriteVirtualMemory(
            h_process,
            user_proc_params as *mut c_void,
            user_proc_params as *mut c_void,
            (*user_proc_params).Length as usize,
            &mut number_of_write,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(format!(
            "[-] NtWriteVirtualMemory Failed With Status: {status}"
        ));
    }

    unsafe {
        if !(*user_proc_params).Environment.is_null() {
            status = NtWriteVirtualMemory(
                h_process,
                (*user_proc_params).Environment,
                (*user_proc_params).Environment,
                (*user_proc_params).EnvironmentSize,
                &mut number_of_write,
            );

            if !NT_SUCCESS(status) {
                return Err(format!(
                    "[-] NtWriteVirtualMemory [2] Failed With Status: {status}"
                ));
            }
        }

        let peb_base_address: *mut PEB = process_basic_information.PebBaseAddress;
        let remote_process_parameters_address = &mut (*peb_base_address).ProcessParameters
            as *mut *mut RTL_USER_PROCESS_PARAMETERS
            as *mut c_void;

        status = NtWriteVirtualMemory(
            h_process,
            remote_process_parameters_address,
            &user_proc_params as *const _ as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            &mut number_of_write,
        );

        if !NT_SUCCESS(status) {
            return Err(format!(
                "[-] NtWriteVirtualMemory [3] Failed With Status: {status}"
            ));
        }
    }

    Ok(peb.ImageBaseAddress)
}
