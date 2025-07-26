use std::ptr::null_mut;

use alloc::vec::Vec;

use super::{
    def::{
        FILE_CREATE, FILE_GENERIC_WRITE, FILE_NON_DIRECTORY_FILE, FILE_PIPE_BYTE_STREAM_MODE,
        FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_QUEUE_OPERATION, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_ATTRIBUTES, GENERIC_READ, IoStatusBlock,
        LargeInteger, OBJ_CASE_INSENSITIVE, OBJ_INHERIT, ObjectAttributes, SYNCHRONIZE,
        SecurityAttributes, UnicodeString, nt_current_teb,
    },
    ntdll::ntdll,
};

use winapi::ctypes::c_void;

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];

        if cur == 0 {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    hsh
}

pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    (tmp - pointer as u64) as _
}

pub fn string_length_w(string: *const u16) -> usize {
    unsafe {
        let mut string2 = string;
        while !(*string2).is_null() {
            string2 = string2.add(1);
        }
        string2.offset_from(string) as usize
    }
}

// Utility function for checking null terminator for u8 and u16
trait IsNull {
    fn is_null(&self) -> bool;
}

impl IsNull for u16 {
    fn is_null(&self) -> bool {
        *self == 0
    }
}

/// Formats a named pipe string and stores it in a `Vec<u16>`
///
/// This function generates a named pipe path in the format:
/// `\\Device\\NamedPipe\\Win32Pipes.<process_id>.<pipe_id>`
/// and stores the UTF-16 encoded string in a `Vec<u16>`.
///
/// # Parameters
/// - `process_id`: The process ID to be included in the pipe name.
/// - `pipe_id`: The pipe ID to be included in the pipe name.
///
/// # Returns
/// A `Vec<u16>` containing the UTF-16 encoded string, null-terminated.
pub fn format_named_pipe_string(process_id: usize, pipe_id: u32) -> Vec<u16> {
    let mut pipe_name_utf16 = Vec::with_capacity(50); // Pre-allocate space

    // Static part of the pipe name
    let device_part = "\\Device\\NamedPipe\\Win32Pipes.";
    pipe_name_utf16.extend(device_part.encode_utf16());

    // Append process_id as a 16-character hex string
    for i in (0..16).rev() {
        let shift = i * 4;
        let hex_digit = ((process_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Append dot separator
    pipe_name_utf16.push('.' as u16);

    // Append pipe_id as an 8-character hex string
    for i in (0..8).rev() {
        let shift = i * 4;
        let hex_digit = ((pipe_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Null-terminate the buffer
    pipe_name_utf16.push(0);

    // Return the UTF-16 encoded vector
    pipe_name_utf16
}

/// Helper function to convert a hex digit (0-15) into its corresponding ASCII character.
///
/// # Returns
/// The corresponding ASCII character as a `u16`.
fn to_hex_char(digit: u16) -> u16 {
    match digit {
        0..=9 => '0' as u16 + digit,
        10..=15 => 'a' as u16 + (digit - 10),
        _ => 0,
    }
}

/// Creates a named pipe and returns handles for reading and writing.
///
/// This function sets up a named pipe with specified security attributes, buffer size,
/// and other options. It creates the pipe with both read and write handles, making it
/// ready for inter-process communication using the `NtCreateNamedPipeFile` NT API function.
pub unsafe fn nt_create_named_pipe_file(
    h_read_pipe: &mut *mut c_void,
    h_write_pipe: &mut *mut c_void,
    lp_pipe_attributes: *mut SecurityAttributes,
    n_size: u32,
    pipe_id: u32,
) -> i32 {
    let mut pipe_name: UnicodeString = UnicodeString::new();
    let mut object_attributes: ObjectAttributes = ObjectAttributes::new();
    let mut status_block: IoStatusBlock = IoStatusBlock::new();
    let mut default_timeout: LargeInteger = LargeInteger::new();
    let mut read_pipe_handle: *mut c_void = null_mut();
    let mut write_pipe_handle: *mut c_void = null_mut();
    let mut security_descriptor: *mut c_void = null_mut();

    // Set the default timeout to 120 seconds
    default_timeout.high_part = -1200000000;

    // Use the default buffer size if not provided
    let n_size = if n_size == 0 { 0x1000 } else { n_size };

    // Format the pipe name using the process ID and pipe ID
    let pipe_name_utf16 = format_named_pipe_string(
        unsafe { nt_current_teb().as_ref().unwrap().client_id.unique_process } as usize,
        pipe_id,
    );

    // Initialize the `UnicodeString` with the formatted pipe name
    pipe_name.init(pipe_name_utf16.as_ptr());

    // Use case-insensitive object attributes by default
    let mut attributes: u32 = OBJ_CASE_INSENSITIVE;

    // Check if custom security attributes were provided
    if !lp_pipe_attributes.is_null() {
        // Use the provided security descriptor
        security_descriptor = unsafe { (*lp_pipe_attributes).lp_security_descriptor };

        // Set the OBJ_INHERIT flag if handle inheritance is requested
        if unsafe { (*lp_pipe_attributes).b_inherit_handle } {
            attributes |= OBJ_INHERIT;
        }
    }

    // Initialize the object attributes for the named pipe
    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut pipe_name,
        attributes, // Case-insensitive and possibly inheritable
        null_mut(),
        security_descriptor,
    );

    // Create the named pipe for reading
    let status = ntdll().nt_create_named_pipe_file.run(
        &mut read_pipe_handle,
        GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, // Desired access: read, write attributes, sync
        &mut object_attributes,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Share mode: allows read/write by other processes
        FILE_CREATE,                        // Creation disposition: create new, fail if exists
        FILE_SYNCHRONOUS_IO_NONALERT,       // Create options: synchronous I/O, no alerts
        FILE_PIPE_BYTE_STREAM_TYPE,         // Pipe type: byte stream (no message boundaries)
        FILE_PIPE_BYTE_STREAM_MODE,         // Read mode: byte stream mode for reading
        FILE_PIPE_QUEUE_OPERATION,          // Completion mode: operations are queued
        1,                                  // Max instances: only one instance of the pipe
        n_size,                             // Inbound quota: input buffer size
        n_size,                             // Outbound quota: output buffer size
        &default_timeout,                   // Default timeout for pipe operations
    );

    // Check if the pipe creation failed
    if status != 0 {
        unsafe { ntdll().nt_close.run(read_pipe_handle) };
        return status;
    }

    let mut status_block_2 = IoStatusBlock::new();

    // Open the pipe for writing
    let status = ntdll().nt_open_file.run(
        &mut write_pipe_handle,
        FILE_GENERIC_WRITE,
        &mut object_attributes,
        &mut status_block_2,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    );

    // Check if the pipe opening failed
    if status != 0 {
        unsafe { ntdll().nt_close.run(read_pipe_handle) };
        return status;
    }

    // Assign the read and write handles to the output parameters
    *h_read_pipe = read_pipe_handle;
    *h_write_pipe = write_pipe_handle;
    0
}
