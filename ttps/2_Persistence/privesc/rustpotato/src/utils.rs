use core::fmt;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

use winapi::shared::ntdef::HANDLE;
use winapi::shared::sddl::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::winbase::LookupAccountSidW;
use winapi::um::winnt::{PSID, SECURITY_DESCRIPTOR};

use winapi::ctypes::c_void;

#[cfg(feature = "verbose")]
use std::io::Error;

/// Macro for conditional printing using `libc_println`.
///
/// The macro takes a format string and optional arguments.
/// It will only print the message if the feature `verbose` is enabled.
#[macro_export]
macro_rules! _print {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose")]
        {
            $crate::libc_println!($($arg)*);
        }
    };
}

/// Reads memory from a specified process at the given address.
///
/// This function attempts to read `size` bytes from the memory of the process
/// identified by `process` starting at `base_address`. If successful, the read
/// data is returned as a `Vec<u8>`. If the read operation fails, an empty vector
/// is returned.
///
/// # Parameters
/// - `process`: A handle to the target process.
/// - `base_address`: The base address from which to read memory.
/// - `size`: The number of bytes to read.
///
/// # Returns
/// A vector containing the read bytes, or an empty vector if the operation fails.
pub fn read_memory(process: HANDLE, base_address: *mut u8, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    unsafe {
        let mut bytes_read = 0;
        if ReadProcessMemory(
            process,
            base_address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        ) != 0
        {
            buffer.truncate(bytes_read as usize); // Adjust size to actual bytes read.
            buffer
        } else {
            Vec::new() // Return an empty vector on failure.
        }
    }
}

/// Implements the Sunday string search algorithm.
///
/// The Sunday algorithm is an efficient pattern matching algorithm
/// that preprocesses the pattern into an occurrence table. This table
/// is then used to shift the search window based on mismatched characters.
pub struct Sunday;

impl Sunday {
    const ALPHA_BET: usize = 512;

    /// Computes the occurrence table for the given pattern.
    ///
    /// This table maps each character to its last occurrence index
    /// within the pattern. Characters not in the pattern are mapped to `-1`.
    ///
    /// # Parameters
    /// - `pattern`: A byte slice representing the pattern to search for.
    ///
    /// # Returns
    /// A table (`[isize; 512]`) with the last occurrence indices for all possible characters.
    fn compute_occurrence(pattern: &[u8]) -> [isize; Self::ALPHA_BET] {
        let mut table = [0isize; Self::ALPHA_BET];

        // Initialize all entries to -1
        for a in 0..Self::ALPHA_BET {
            table[a] = -1;
        }

        // Fill the table based on the pattern
        for (i, &byte) in pattern.iter().enumerate() {
            table[byte as usize] = i as isize;
        }

        table
    }

    /// Searches for all occurrences of a pattern in the given text using the Sunday algorithm.
    ///
    /// # Parameters
    /// - `text`: A byte slice representing the text to search within.
    /// - `pattern`: A byte slice representing the pattern to search for.
    ///
    /// # Returns
    /// A vector of start indices where the pattern matches in the text.
    pub fn search(text: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        let table = Self::compute_occurrence(pattern);

        let mut i = 0;
        while i <= text.len().saturating_sub(pattern.len()) {
            let mut j = 0;

            // Match the pattern with the text
            while j < pattern.len() && text[i + j] == pattern[j] {
                j += 1;
            }

            // If a full match is found, record the index
            if j == pattern.len() {
                matches.push(i);
            }

            i += pattern.len();
            if i < text.len() {
                let shift = table[text[i] as usize];
                if shift != -1 {
                    i -= shift as usize;
                }
            }
        }

        matches
    }
}

/// Creates a security descriptor from a string descriptor.
///
/// This function converts a string representation of a security descriptor
/// into a binary security descriptor. The resulting security descriptor can
/// be used in various Windows API calls that require access control.
///
/// # Parameters
/// - `descriptor_string`: A string describing the security descriptor in
///   Security Descriptor Definition Language (SDDL).
///
/// # Returns
/// An `Option` containing:
/// - A pointer to the created `SECURITY_DESCRIPTOR`.
/// - The size of the security descriptor in bytes.
/// Returns `None` if the creation fails.
pub fn create_security_descriptor(
    descriptor_string: &str,
) -> Option<(*mut SECURITY_DESCRIPTOR, u32)> {
    unsafe {
        // Convert the descriptor string to a wide string (UTF-16).
        let wide_descriptor: Vec<u16> = descriptor_string.encode_utf16().chain(Some(0)).collect();
        let mut security_descriptor: *mut SECURITY_DESCRIPTOR = core::ptr::null_mut();
        let mut security_descriptor_size: u32 = 0;

        // Call the Windows API to convert the string to a security descriptor.
        let result = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_descriptor.as_ptr() as *mut _,
            1, // Revision
            &mut security_descriptor as *mut _ as *mut _,
            &mut security_descriptor_size,
        ) != 0;

        if result {
            Some((security_descriptor, security_descriptor_size))
        } else {
            _print!(
                "[-] Failed to create security descriptor with error: {:?}",
                Error::last_os_error()
            );
            None
        }
    }
}

/// Represents a GUID (Globally Unique Identifier).
///
/// Encapsulates GUID functionality, including conversion to/from byte representations.
#[derive(Debug, Clone)]
pub struct GUID {
    pub value: String,
}

impl GUID {
    /// Creates a new GUID from a given string value.
    pub fn new(value: String) -> GUID {
        GUID { value: value }
    }

    /// Constructs a GUID from a byte slice.
    /// The byte slice must be exactly 16 bytes in length to match the GUID format.
    /// Returns an error if the byte slice length is not 16.
    pub fn from_bytes(bytes: &[u8]) -> Result<GUID, Box<dyn core::error::Error>> {
        // Validate that the byte slice has the correct length for a GUID
        if bytes.len() != 16 {
            return Err("GUID length is incorrect, must be 16 bytes".into());
        }

        // Parse each part of the GUID according to the GUID format:
        // 8-4-4-4-12 hex digits (16 bytes in total)

        // First part: 4 bytes, stored as a 32-bit integer (little-endian)
        let part1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        // Second part: 2 bytes, stored as a 16-bit integer (little-endian)
        let part2 = u16::from_le_bytes([bytes[4], bytes[5]]);

        // Third part: 2 bytes, stored as a 16-bit integer (little-endian)
        let part3 = u16::from_le_bytes([bytes[6], bytes[7]]);

        // Fourth part: 2 bytes, represented as two separate bytes in the format
        let part4 = &bytes[8..10];

        // Fifth part: 6 bytes, represented as individual bytes in the format
        let part5 = &bytes[10..16];

        // Format the GUID string using the standard 8-4-4-4-12 hexadecimal format
        let guid_string = format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            part1,
            part2,
            part3,
            part4[0],
            part4[1],
            part5[0],
            part5[1],
            part5[2],
            part5[3],
            part5[4],
            part5[5]
        );

        // Return the newly created GUID with the formatted string
        Ok(GUID { value: guid_string })
    }

    /// Converts the GUID into its raw byte representation.
    /// The resulting byte array is in the standard little-endian format.
    pub fn to_le_bytes(&self) -> Result<[u8; 16], Box<dyn core::error::Error>> {
        // Validate that the GUID is in the correct format (8-4-4-4-12)
        let parts: Vec<&str> = self.value.split('-').collect();
        if parts.len() != 5 {
            return Err("Invalid GUID format".into());
        }

        // Parse the components of the GUID
        let part1 = u32::from_str_radix(parts[0], 16)?;
        let part2 = u16::from_str_radix(parts[1], 16)?;
        let part3 = u16::from_str_radix(parts[2], 16)?;
        let part4 = u16::from_str_radix(parts[3], 16)?;
        let part5 = u64::from_str_radix(parts[4], 16)?;

        // Combine the parts into the byte array
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&part1.to_le_bytes());
        bytes[4..6].copy_from_slice(&part2.to_le_bytes());
        bytes[6..8].copy_from_slice(&part3.to_le_bytes());
        bytes[8..10].copy_from_slice(&part4.to_be_bytes()[..2]);
        bytes[10..16].copy_from_slice(&part5.to_be_bytes()[2..8]);

        Ok(bytes)
    }
}

/// Represents a Security Identifier (SID).
///
/// Provides methods to parse a SID from bytes or a pointer.
#[derive(Default, Debug, Clone)]
pub struct Sid {
    /// The string representation of the SID.
    pub value: String,
}

impl Sid {
    /// Constructs a SID from a byte slice.
    /// The byte slice must follow the SID binary format.
    /// Returns an error if the byte slice is too short or invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Sid> {
        // Check if the byte slice has a valid length for SID
        if bytes.len() < 8 {
            return None;
        }

        let revision = bytes[0];
        let sub_authority_count = bytes[1];
        let identifier_authority = &bytes[2..8];

        // Initialize SID string format with revision
        let mut value = format!("S-{}", revision);

        // Convert identifier authority bytes to a single u64 value
        let mut id_auth_value = 0u64;
        for &b in identifier_authority {
            id_auth_value = (id_auth_value << 8) + b as u64;
        }
        value += &format!("-{}", id_auth_value);

        // Calculate required length for sub-authorities and validate it
        if bytes.len() < 8 + (sub_authority_count as usize) * 4 {
            return None;
        }

        // Parse each sub-authority (32-bit values in little-endian format)
        for i in 0..sub_authority_count {
            let offset = 8 + (i as usize) * 4;
            let sub_auth_bytes = &bytes[offset..offset + 4];
            let sub_auth = u32::from_le_bytes([
                sub_auth_bytes[0],
                sub_auth_bytes[1],
                sub_auth_bytes[2],
                sub_auth_bytes[3],
            ]);
            value += &format!("-{}", sub_auth);
        }

        Some(Sid { value })
    }

    pub fn from_ptr(ptr: *mut c_void) -> Option<Sid> {
        if ptr.is_null() {
            return None;
        }

        unsafe {
            // Interpret the pointer as a byte slice
            let sid_bytes = core::slice::from_raw_parts(ptr as *const u8, 8);

            // Check the minimum SID length
            if sid_bytes.len() < 8 {
                return None;
            }

            // Retrieve the revision and sub-authority count
            // let revision = sid_bytes[0];
            let sub_authority_count = sid_bytes[1] as usize;

            // Calculate the total SID length based on sub-authority count
            let expected_length = 8 + (4 * sub_authority_count);
            let sid_data = core::slice::from_raw_parts(ptr as *const u8, expected_length);

            // Call your existing SID parsing function with the byte slice
            Sid::from_bytes(sid_data)
        }
    }

    pub fn to_ptr(&self) -> *mut winapi::ctypes::c_void {
        let wide_sid: Vec<u16> = OsStr::new(self.value.as_str())
            .encode_wide()
            .chain(Some(0))
            .collect();

        let mut sid: PSID = core::ptr::null_mut();
        let result = unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &mut sid) };

        if result == 0 {
            core::ptr::null_mut() as *mut winapi::ctypes::c_void
        } else {
            sid as *mut winapi::ctypes::c_void
        }
    }

    pub fn to_username(&self) -> Option<TokenUsername> {
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let mut name_size = 256;
        let mut domain_size = 256;
        let mut sid_type = 0;

        // Resolve the SID to its corresponding name and domain
        let result = unsafe {
            LookupAccountSidW(
                core::ptr::null(),                   // Local system
                self.to_ptr(),                       // SID to lookup
                name.as_mut_ptr(),                   // Buffer for the name
                &mut name_size,                      // Size of the name buffer
                domain.as_mut_ptr(),                 // Buffer for the domain
                &mut domain_size,                    // Size of the domain buffer
                &mut sid_type as *mut _ as *mut u32, // SID type
            )
        };

        if result == 0 {
            // If lookup fails, return an error
            return None;
        }

        // Convert the name and domain into readable strings
        let name_string = OsString::from_wide(&name[..name_size as usize])
            .to_string_lossy()
            .into_owned();
        let domain_string = OsString::from_wide(&domain[..domain_size as usize])
            .to_string_lossy()
            .into_owned();

        Some(TokenUsername::new(name_string, domain_string))
    }
}

#[derive(Debug, Clone)]
/// Represents a username tied to a token, including both the name and domain.
pub struct TokenUsername {
    pub name: String,
    pub domain: String,
}

impl TokenUsername {
    /// Creates a new `TokenUsername` with the specified name and domain.
    pub fn new(name: String, domain: String) -> TokenUsername {
        TokenUsername { name, domain }
    }
}

impl fmt::Display for TokenUsername {
    /// Formats the username in the "DOMAIN\Name" style.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\\{}", self.domain, self.name)
    }
}

/// Represents a raw pointer to a Windows handle, designed for thread-safe operations.
///
/// This structure wraps a raw pointer to a Windows handle (`HANDLE`) and provides
/// utilities to safely work with it in a Rust context. The `Send` and `Sync` traits are
/// implemented to allow safe transfer and sharing of handles across threads.
///
/// In the context of this project, `RawHandle` is used to store and manage system tokens
/// retrieved during impersonation. By encapsulating the raw pointer, it ensures flexibility
/// for thread-based operations while maintaining Rust's safety guarantees.
#[derive(Debug, Clone, Copy)]
pub struct RawHandle(*mut winapi::ctypes::c_void);

impl RawHandle {
    /// Converts the internal raw pointer into a Windows `HANDLE`.
    ///
    /// # Returns
    /// - The `HANDLE` representation of the raw pointer.
    pub fn as_handle(&self) -> winapi::um::winnt::HANDLE {
        self.0 as winapi::um::winnt::HANDLE
    }
}

unsafe impl Send for RawHandle {}
unsafe impl Sync for RawHandle {}

/// Represents a Windows security identity with an optional token.
///
/// This structure is designed to store and manage a security token associated with a Windows
/// identity. It provides methods to set and retrieve the token, allowing the identity to be
/// used in privileged operations such as creating processes or accessing restricted resources.
///
/// In this project, `WindowsIdentity` plays a key role in persisting the system token retrieved
/// during the impersonation of a pipe client. Once the token is stored, it can be accessed later
/// to spawn new processes with the elevated privileges of the system account.
///
/// # Usage
/// - `set_token`: Used to store a raw handle to a security token.
/// - `get_token`: Retrieves the stored token for use in privileged operations.
///
/// This struct is thread-safe and is typically used in conjunction with synchronization
/// primitives like `Arc<Mutex<WindowsIdentity>>` to share the token across threads.
#[derive(Clone, Default)]
pub struct WindowsIdentity {
    /// The security token associated with this identity, wrapped in a `RawHandle`.
    pub token: Option<RawHandle>,
}

impl WindowsIdentity {
    /// Stores a raw handle to a security token.
    ///
    /// # Parameters
    /// - `p`: A raw pointer to the token handle to be stored.
    pub fn set_token(&mut self, p: *mut winapi::ctypes::c_void) {
        self.token = Some(RawHandle(p));
    }

    /// Retrieves the stored security token.
    ///
    /// # Returns
    /// - `Some(RawHandle)` if a token has been stored.
    /// - `None` if no token is currently set.
    pub fn get_token(&self) -> Option<RawHandle> {
        self.token.clone()
    }
}
