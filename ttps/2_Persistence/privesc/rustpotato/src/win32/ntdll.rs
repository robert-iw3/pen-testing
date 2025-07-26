use core::{
    ffi::c_uint,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use winapi::ctypes::c_void;

use crate::{
    define_nt_syscall, resolve_native_functions, run_syscall,
    win32::{
        def::{ClientId, ObjectAttributes, UnicodeString},
        ldr::{ldr_function, ldr_module},
    },
};

use super::def::{IoStatusBlock, LargeInteger, nt_current_teb};

/// Retrieves a handle to the current process.
///
/// # Returns
///
/// A handle to the current process.
pub const fn nt_current_process() -> *mut c_void {
    -1isize as *mut c_void
}

/// Gets the last error value for the current thread.
///
/// This function retrieves the last error code set in the Thread Environment Block (TEB).
/// It mimics the behavior of the `NtGetLastError` macro in C.
///
/// # Safety
/// This function involves unsafe operations and raw pointers, which require careful handling.
pub fn nt_get_last_error() -> u32 {
    unsafe { nt_current_teb().as_ref().unwrap().last_error_value }
}

#[allow(dead_code)]
pub trait NtSyscall {
    /// Create a new syscall object
    fn new() -> Self;
    /// The number of the syscall
    fn number(&self) -> u16;
    /// The address of the syscall
    fn address(&self) -> *mut u8;
    /// The hash of the syscall (used for lookup)
    fn hash(&self) -> usize;
}

define_nt_syscall!(NtClose, 0x40d6e69d);

impl NtClose {
    /// Wrapper function for NtClose to avoid repetitive run_syscall calls.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to an object. This is a required parameter that must be valid.
    ///   It represents the handle that will be closed by the function.
    ///
    /// # Returns
    ///
    /// * `true` if the operation was successful, `false` otherwise. The function returns an
    ///   NTSTATUS code; however, in this wrapper, the result is simplified to a boolean.
    pub unsafe fn run(&self, handle: *mut c_void) -> i32 {
        run_syscall!(self.number, self.address as usize, handle)
    }
}

define_nt_syscall!(NtQuerySystemInformation, 0x7bc23928);
impl NtQuerySystemInformation {
    /// Wrapper for the NtQuerySystemInformation
    ///
    /// # Arguments
    ///
    /// * `[in]` - `system_information_class` The system information class to be queried.
    /// * `[out]` - `system_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `system_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `system_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes,
    ///   of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            system_information_class,
            system_information,
            system_information_length,
            return_length
        )
    }
}

define_nt_syscall!(NtOpenProcess, 0x4b82f718);
impl NtOpenProcess {
    /// Wrapper for the NtOpenProcess
    ///
    /// # Arguments
    ///
    /// * `[out]` - `process_handle` A mutable pointer to a handle that will receive the process
    ///   handle.
    /// * `[in]` - `desired_access` The desired access for the process.
    /// * `[in]` - `object_attributes` A pointer to the object attributes structure.
    /// * `[in, opt]` - `client_id` A pointer to the client ID structure.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        process_handle: &mut *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
        client_id: *mut ClientId,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            client_id as *mut _ as *mut c_void
        )
    }
}

define_nt_syscall!(NtOpenProcessToken, 0x350dca99);
impl NtOpenProcessToken {
    /// Wrapper for the NtOpenProcessToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` The handle of the process whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access for the token.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        process_handle: *mut c_void,
        desired_access: u32,
        token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            desired_access,
            token_handle
        )
    }
}

define_nt_syscall!(NtDuplicateToken, 0x8e160b23);
impl NtDuplicateToken {
    /// Wrapper for the NtOpenProcessToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` The handle of the process whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access for the token.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        existing_token_handle: *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
        effective_level: u8,
        token_type: u32,
        new_token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            existing_token_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            effective_level as c_uint,
            token_type,
            new_token_handle
        )
    }
}

define_nt_syscall!(NtQueryInformationToken, 0xf371fe4);
impl NtQueryInformationToken {
    /// Wrapper for the NtQueryInformationToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `token_handle` The handle of the token to be queried.
    /// * `[in]` - `token_information_class` The class of information to be queried.
    /// * `[out]` - `token_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `token_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `token_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes,
    ///   of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        token_handle: *mut c_void,
        token_information_class: u32,
        token_information: *mut c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            token_handle,
            token_information_class,
            token_information,
            token_information_length,
            return_length
        )
    }
}

define_nt_syscall!(NtCreateNamedPipeFile, 0x1da0062e);

impl NtCreateNamedPipeFile {
    /// Wrapper for the NtCreateNamedPipeFile syscall.
    ///
    /// This function creates a named pipe file and returns a handle to it.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A mutable pointer to a handle that will receive the file handle.
    /// * `[in]` - `desired_access` The desired access rights for the named pipe file.
    /// * `[in]` - `object_attributes` A pointer to an `OBJECT_ATTRIBUTES` structure that specifies the object attributes.
    /// * `[out]` - `io_status_block` A pointer to an `IO_STATUS_BLOCK` structure that receives the status of the I/O operation.
    /// * `[in]` - `share_access` The requested sharing mode of the file.
    /// * `[in]` - `create_disposition` Specifies the action to take on files that exist or do not exist.
    /// * `[in]` - `create_options` Specifies the options to apply when creating or opening the file.
    /// * `[in]` - `named_pipe_type` Specifies the type of named pipe (byte stream or message).
    /// * `[in]` - `read_mode` Specifies the read mode for the pipe.
    /// * `[in]` - `completion_mode` Specifies the completion mode for the pipe.
    /// * `[in]` - `maximum_instances` The maximum number of instances of the pipe.
    /// * `[in]` - `inbound_quota` The size of the input buffer, in bytes.
    /// * `[in]` - `outbound_quota` The size of the output buffer, in bytes.
    /// * `[in, opt]` - `default_timeout` A pointer to a `LARGE_INTEGER` structure that specifies the default time-out value.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        named_pipe_type: u32,
        read_mode: u32,
        completion_mode: u32,
        maximum_instances: u32,
        inbound_quota: u32,
        outbound_quota: u32,
        default_timeout: *const LargeInteger,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            create_disposition,
            create_options,
            named_pipe_type,
            read_mode,
            completion_mode,
            maximum_instances,
            inbound_quota,
            outbound_quota,
            default_timeout
        )
    }
}

define_nt_syscall!(NtOpenFile, 0x46dde739);
impl NtOpenFile {
    /// Wrapper for the NtOpenFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A pointer to a handle that receives the file handle.
    /// * `[in]` - `desired_access` The desired access for the file handle.
    /// * `[in]` - `object_attributes` A pointer to the OBJECT_ATTRIBUTES structure.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the status block.
    /// * `[in]` - `share_access` The requested share access for the file.
    /// * `[in]` - `open_options` The options to be applied when opening the file.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: &mut *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
        io_status_block: &mut IoStatusBlock,
        share_access: u32,
        open_options: u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options
        )
    }
}

define_nt_syscall!(NtWriteFile, 0xe0d61db2);
impl NtWriteFile {
    /// Wrapper for the NtWriteFile syscall.
    ///
    /// This function writes data to a file or I/O device. It wraps the NtWriteFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `file_handle` A handle to the file or I/O device to be written to.
    /// * `[in, opt]` - `event` An optional handle to an event object that will be signaled when the operation completes.
    /// * `[in, opt]` - `apc_routine` An optional pointer to an APC routine to be called when the operation completes.
    /// * `[in, opt]` - `apc_context` An optional pointer to a context for the APC routine.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[in]` - `buffer` A pointer to a buffer that contains the data to be written to the file or device.
    /// * `[in]` - `length` The length, in bytes, of the buffer pointed to by the `buffer` parameter.
    /// * `[in, opt]` - `byte_offset` A pointer to the byte offset in the file where the operation should begin. If this parameter is `None`, the system writes data to the current file position.
    /// * `[in, opt]` - `key` A pointer to a caller-supplied variable to receive the I/O completion key. This parameter is ignored if `event` is not `None`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut c_void,
        event: *mut c_void,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: &mut IoStatusBlock,
        buffer: *mut c_void,
        length: u32,
        byte_offset: *mut u64,
        key: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key
        )
    }
}

define_nt_syscall!(NtReadFile, 0xb2d93203);

impl NtReadFile {
    /// Wrapper for the NtReadFile syscall.
    ///
    /// This function reads data from a file or I/O device. It wraps the NtReadFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `file_handle` A handle to the file or I/O device to be read from.
    /// * `[in, opt]` - `event` An optional handle to an event object that will be signaled when the operation completes.
    /// * `[in, opt]` - `apc_routine` An optional pointer to an APC routine to be called when the operation completes.
    /// * `[in, opt]` - `apc_context` An optional pointer to a context for the APC routine.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[out]` - `buffer` A pointer to a buffer that receives the data read from the file or device.
    /// * `[in]` - `length` The length, in bytes, of the buffer pointed to by the `buffer` parameter.
    /// * `[in, opt]` - `byte_offset` A pointer to the byte offset in the file where the operation should begin. If this parameter is `None`, the system reads data from the current file position.
    /// * `[in, opt]` - `key` A pointer to a caller-supplied variable to receive the I/O completion key. This parameter is ignored if `event` is not `None`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut c_void,
        event: *mut c_void,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: &mut IoStatusBlock,
        buffer: *mut c_void,
        length: u32,
        byte_offset: *mut u64,
        key: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key
        )
    }
}

define_nt_syscall!(NtQueryInformationProcess, 0x8cdc5dc2);
impl NtQueryInformationProcess {
    /// Wrapper for the NtQueryInformationProcess
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences the `process_handle`, `process_information`,
    /// and `return_length` pointers.
    ///
    /// The caller must ensure that the pointers are valid and that the memory they point to is
    /// valid and has the correct size.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` A handle to the process.
    /// * `[in]` - `process_information_class` The class of information to be queried.
    /// * `[out]` - `process_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `process_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `process_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes,
    ///   of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        process_handle: *mut c_void,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            process_information_class,
            process_information,
            process_information_length,
            return_length
        )
    }
}

define_nt_syscall!(NtDuplicateObject, 0x4441d859); // Replace `0xabcdef12` with the correct hash for `NtDuplicateObject`.

impl NtDuplicateObject {
    /// Wrapper for the NtDuplicateObject syscall.
    ///
    /// This function duplicates an object handle, allowing the handle to be shared across processes
    /// or duplicated with a different set of access rights or attributes.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `source_process_handle` A handle to the process containing the source handle.
    /// * `[in]` - `source_handle` The handle to be duplicated.
    /// * `[in, opt]` - `target_process_handle` A handle to the process to receive the duplicated handle.
    /// * `[out]` - `target_handle` A pointer to a variable that receives the duplicated handle.
    /// * `[in]` - `desired_access` The desired access rights for the duplicated handle.
    /// * `[in]` - `handle_attributes` The attributes for the duplicated handle (e.g., inheritable).
    /// * `[in]` - `options` Flags that specify optional behavior for the operation.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub fn run(
        &self,
        source_process_handle: *mut c_void,
        source_handle: *mut c_void,
        target_process_handle: *mut c_void,
        target_handle: &mut *mut c_void,
        desired_access: u32,
        handle_attributes: u32,
        options: u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            source_process_handle,
            source_handle,
            target_process_handle,
            target_handle,
            desired_access,
            handle_attributes,
            options
        )
    }
}

define_nt_syscall!(NtWaitForSingleObject, 0xe8ac0c3c);
impl NtWaitForSingleObject {
    /// Wrapper for the NtWaitForSingleObject
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences the `handle` and `timeout` pointers.
    ///
    /// The caller must ensure that the pointers are valid and that the memory they point to is
    /// valid and has the correct size.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to the object.
    /// * `[in]` - `alertable` A boolean value that specifies whether the wait is alertable.
    /// * `[in, opt]` - `timeout` An optional pointer to a time-out value.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(&self, handle: *mut c_void, alertable: bool, timeout: *mut c_void) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            handle,
            alertable as u32,
            timeout
        )
    }
}

define_nt_syscall!(NtQueryObject, 0xc85dc9b4); // Replace `0xABCDE123` with the correct hash for `NtQueryObject`.

impl NtQueryObject {
    /// Wrapper for the NtQueryObject syscall.
    ///
    /// This function queries information about an object handle.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to the object to be queried.
    /// * `[in]` - `object_information_class` The type of information to retrieve about the object.
    /// * `[out]` - `object_information` A pointer to a buffer that receives the requested information.
    /// * `[in]` - `object_information_length` The size, in bytes, of the buffer pointed to by `object_information`.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size of the data returned, if applicable.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub fn run(
        &self,
        handle: *mut c_void,
        object_information_class: u32,
        object_information: *mut c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            handle,
            object_information_class,
            object_information,
            object_information_length,
            return_length
        )
    }
}

define_nt_syscall!(NtSetInformationObject, 0x214310); // Replace `0x12345ABC` with the correct hash for `NtSetInformationObject`.

impl NtSetInformationObject {
    /// Wrapper for the NtSetInformationObject syscall.
    ///
    /// This function sets information about an object handle.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to the object to be modified.
    /// * `[in]` - `object_information_class` The type of information to set for the object.
    /// * `[in]` - `object_information` A pointer to a buffer containing the information to be set.
    /// * `[in]` - `object_information_length` The size, in bytes, of the buffer pointed to by `object_information`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub fn run(
        &self,
        handle: *mut c_void,
        object_information_class: u32,
        object_information: *mut c_void,
        object_information_length: u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            handle,
            object_information_class,
            object_information,
            object_information_length
        )
    }
}

define_nt_syscall!(NtTerminateProcess, 0x4ed9dd4f);
impl NtTerminateProcess {
    /// Wrapper for the NtTerminateProcess
    ///
    /// This function terminates a process. It wraps the NtTerminateProcess
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences the `process_handle` pointer.
    ///
    /// Pointer validity must be ensured by the caller.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - A handle to the process to be terminated.
    /// * `exit_status` - The exit status to be returned by the process.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(&self, process_handle: *mut c_void, exit_status: i32) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            exit_status
        )
    }
}

define_nt_syscall!(NtProtectVirtualMemory, 0x50e92888);

impl NtProtectVirtualMemory {
    /// Wrapper for the NtProtectVirtualMemory
    ///
    /// This function changes the protection on a region of memory within the virtual address space
    /// of a specified process. It wraps the NtProtectVirtualMemory system call.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences the `process_handle`, `base_address`,
    /// `region_size`, and `new_protect` pointers.
    ///
    /// The caller must ensure that the pointers are valid and that the memory they point to is
    /// valid and has the correct size.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` A handle to the process whose memory protection is to be changed.
    /// * `[in, out]` - `base_address` A pointer to a variable that specifies the base address of
    ///   the region of memory to be changed. The value of this parameter is updated by the function.
    /// * `[in, out]` - `region_size` A pointer to a variable that specifies the size of the region
    ///   of memory to be changed, in bytes.
    /// * `[in]` - `new_protect` The new protection attributes for the memory region. This parameter
    ///   can include values such as `PAGE_READWRITE`, `PAGE_EXECUTE`, etc.
    /// * `[out]` - `old_protect` A pointer to a variable that receives the old protection attributes
    ///   of the region of memory.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure of the system call.
    pub unsafe fn run(
        &self,
        process_handle: *mut c_void,
        base_address: &mut *mut c_void,
        region_size: &mut usize,
        new_protect: u32,
        old_protect: &mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            base_address,
            region_size,
            new_protect,
            old_protect
        )
    }
}

/// Type definition for the LdrLoadDll function.
///
/// Loads a DLL into the address space of the calling process.
///
/// # Parameters
/// - `[in, opt]` - `DllPath`: A pointer to a `UNICODE_STRING` that specifies the fully qualified path of the DLL to load. This can be `NULL`, in which case the system searches for the DLL.
/// - `[in, opt]` - `DllCharacteristics`: A pointer to a variable that specifies the DLL characteristics (optional, can be `NULL`).
/// - `[in]` - `DllName`: A `UNICODE_STRING` that specifies the name of the DLL to load.
/// - `[out]` - `DllHandle`: A pointer to a variable that receives the handle to the loaded DLL.
///
/// # Returns
/// - `i32` - The NTSTATUS code of the operation.
type LdrLoadDll = unsafe extern "system" fn(
    DllPath: *mut u16,
    DllCharacteristics: *mut u32,
    DllName: UnicodeString,
    DllHandle: *mut c_void,
) -> i32;

/// Type definition for the RtlAllocateHeap function.
///
/// Allocates a block of memory from the specified heap. The allocated memory is uninitialized.
///
/// # Parameters
/// - `[in]` - `hHeap`: A handle to the heap from which the memory will be allocated.
/// - `[in]` - `dwFlags`: Flags that control aspects of the allocation, such as whether to generate
///   exceptions on failure.
/// - `[in]` - `dwBytes`: The number of bytes to allocate from the heap.
///
/// # Returns
/// - `*mut u8`: A pointer to the allocated memory block. If the allocation fails, the pointer will
///   be `NULL`.
pub type RtlAllocateHeap =
    unsafe extern "system" fn(hHeap: *mut c_void, dwFlags: u32, dwBytes: usize) -> *mut u8;

/// Represents the `NTDLL` library and its functions.
pub struct NtDll {
    pub module_base: *mut u8,
    pub ldr_load_dll: LdrLoadDll,
    pub nt_close: NtClose,
    pub nt_open_process: NtOpenProcess,
    pub nt_query_system_information: NtQuerySystemInformation,
    pub nt_open_process_token: NtOpenProcessToken,
    pub nt_duplicate_token: NtDuplicateToken,
    pub nt_query_information_token: NtQueryInformationToken,
    pub nt_create_named_pipe_file: NtCreateNamedPipeFile,
    pub nt_open_file: NtOpenFile,
    pub nt_write_file: NtWriteFile,
    pub nt_read_file: NtReadFile,
    pub nt_query_information_process: NtQueryInformationProcess,
    pub nt_duplicate_object: NtDuplicateObject,
    pub nt_wait_for_single_object: NtWaitForSingleObject,
    pub nt_query_object: NtQueryObject,
    pub nt_set_information_object: NtSetInformationObject,
    pub rtl_allocate_heap: Option<RtlAllocateHeap>,
    pub nt_terminate_process: NtTerminateProcess,
    pub nt_protect_virtual_memory: NtProtectVirtualMemory,
}

impl NtDll {
    pub fn new() -> Self {
        NtDll {
            module_base: null_mut(),
            ldr_load_dll: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            nt_close: NtClose::new(),
            nt_open_process: NtOpenProcess::new(),
            nt_query_system_information: NtQuerySystemInformation::new(),
            nt_open_process_token: NtOpenProcessToken::new(),
            nt_duplicate_token: NtDuplicateToken::new(),
            nt_query_information_token: NtQueryInformationToken::new(),
            nt_create_named_pipe_file: NtCreateNamedPipeFile::new(),
            nt_open_file: NtOpenFile::new(),
            nt_write_file: NtWriteFile::new(),
            nt_read_file: NtReadFile::new(),
            nt_query_information_process: NtQueryInformationProcess::new(),
            nt_duplicate_object: NtDuplicateObject::new(),
            nt_wait_for_single_object: NtWaitForSingleObject::new(),
            nt_query_object: NtQueryObject::new(),
            nt_set_information_object: NtSetInformationObject::new(),
            rtl_allocate_heap: None,
            nt_terminate_process: NtTerminateProcess::new(),
            nt_protect_virtual_memory: NtProtectVirtualMemory::new(),
        }
    }
}

/// Atomic flag to ensure initialization happens only once.
static INIT_NTDLL: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of the ntdll.
// pub static mut NTDLL: RwLock<UnsafeCell<Option<NtDll>>> = RwLock::new(UnsafeCell::new(None));

static mut NTDLL_PTR: *const NtDll = core::ptr::null();

/// Returns a static reference to the `NtDll` instance, ensuring it is initialized before use.
pub fn ntdll() -> &'static NtDll {
    ensure_initialized();
    unsafe { &*NTDLL_PTR }
}

/// Ensures the `NtDll` library is initialized before any function pointers are used.
fn ensure_initialized() {
    if !INIT_NTDLL.load(Ordering::Acquire) {
        init_ntdll_funcs();
    }
}

/// Initializes the `NtDll` library by loading `ntdll.dll` and resolving function pointers.
pub fn init_ntdll_funcs() {
    // Check if initialization has already occurred.
    if !INIT_NTDLL.load(Ordering::Acquire) {
        let mut ntdll = NtDll::new();

        ntdll.module_base = unsafe { ldr_module(0x1edab0ed, None) };

        // Resolve LdrLoadDll
        let ldr_load_dll_addr = unsafe { ldr_function(ntdll.module_base, 0x9e456a43) };
        ntdll.ldr_load_dll = unsafe { core::mem::transmute(ldr_load_dll_addr) };

        let rtl_allocate_heap_addr = unsafe { ldr_function(ntdll.module_base, 0x3be94c5a) };
        ntdll.rtl_allocate_heap = unsafe { core::mem::transmute(rtl_allocate_heap_addr) };

        resolve_native_functions!(
            ntdll.module_base,
            ntdll.nt_close,
            ntdll.nt_open_process,
            ntdll.nt_query_system_information,
            ntdll.nt_open_process_token,
            ntdll.nt_duplicate_token,
            ntdll.nt_query_information_token,
            ntdll.nt_create_named_pipe_file,
            ntdll.nt_open_file,
            ntdll.nt_write_file,
            ntdll.nt_read_file,
            ntdll.nt_query_information_process,
            ntdll.nt_duplicate_object,
            ntdll.nt_wait_for_single_object,
            ntdll.nt_query_object,
            ntdll.nt_set_information_object,
            ntdll.nt_terminate_process,
            ntdll.nt_protect_virtual_memory
        );

        unsafe { NTDLL_PTR = Box::into_raw(Box::new(ntdll)) };

        // Set the initialization flag to true.
        INIT_NTDLL.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_ntdll_syscalls() {
        // Inizializza la libreria ntdll
        init_ntdll_funcs();

        // Ottieni il riferimento statico alla struttura NtDll
        let ntdll = ntdll();

        // Stampa intestazione
        println!("{:<30} {:<10} {:<20}", "Function", "SSN", "Address");

        // Stampa i dettagli delle funzioni
        println!(
            "{:<30} {:<10} {:<20}",
            "NtClose",
            ntdll.nt_close.number(),
            format!("{:?}", ntdll.nt_close.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtOpenProcess",
            ntdll.nt_open_process.number(),
            format!("{:?}", ntdll.nt_open_process.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtQuerySystemInformation",
            ntdll.nt_query_system_information.number(),
            format!("{:?}", ntdll.nt_query_system_information.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtOpenProcessToken",
            ntdll.nt_open_process_token.number(),
            format!("{:?}", ntdll.nt_open_process_token.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtDuplicateToken",
            ntdll.nt_duplicate_token.number(),
            format!("{:?}", ntdll.nt_duplicate_token.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtQueryInformationToken",
            ntdll.nt_query_information_token.number(),
            format!("{:?}", ntdll.nt_query_information_token.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtCreateNamedPipeFile",
            ntdll.nt_create_named_pipe_file.number(),
            format!("{:?}", ntdll.nt_create_named_pipe_file.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtOpenFile",
            ntdll.nt_open_file.number(),
            format!("{:?}", ntdll.nt_open_file.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtWriteFile",
            ntdll.nt_write_file.number(),
            format!("{:?}", ntdll.nt_write_file.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtReadFile",
            ntdll.nt_read_file.number(),
            format!("{:?}", ntdll.nt_read_file.address())
        );
        println!(
            "{:<30} {:<10} {:<20}",
            "NtQueryInformationProcess",
            ntdll.nt_query_information_process.number(),
            format!("{:?}", ntdll.nt_query_information_process.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtDuplicateObject",
            ntdll.nt_duplicate_object.number(),
            format!("{:?}", ntdll.nt_duplicate_object.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtWaitForSingleObject",
            ntdll.nt_wait_for_single_object.number(),
            format!("{:?}", ntdll.nt_wait_for_single_object.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtQueryObject",
            ntdll.nt_query_object.number(),
            format!("{:?}", ntdll.nt_query_object.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtSetInformationObject",
            ntdll.nt_set_information_object.number(),
            format!("{:?}", ntdll.nt_set_information_object.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtTerminateProcess",
            ntdll.nt_terminate_process.number(),
            format!("{:?}", ntdll.nt_terminate_process.address())
        );

        println!(
            "{:<30} {:<10} {:<20}",
            "NtProtectVirtualMemory",
            ntdll.nt_protect_virtual_memory.number(),
            format!("{:?}", ntdll.nt_protect_virtual_memory.address())
        );
    }
}
