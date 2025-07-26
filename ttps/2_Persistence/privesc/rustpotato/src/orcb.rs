use std::{
    alloc::{Layout, alloc_zeroed},
    ffi::c_void,
    ptr,
};

use crate::context::GLOBAL_CONTEXT;

/// Represents a handler for setting up RPC bindings dynamically.
#[derive(Clone, Default)]
pub struct NewOrcbRPC;

impl NewOrcbRPC {
    /// Sets up new bindings for the RPC endpoints dynamically.
    ///
    /// This function allocates memory for binding strings, initializes the structure,
    /// and assigns it to the provided output pointer.
    ///
    /// # Parameters
    /// - `ppdsa_new_bindings`: A mutable pointer to a pointer where the newly created binding structure will be stored.
    /// - `_ppdsa_new_security`: Reserved for future use (currently unused).
    ///
    /// # Returns
    /// - `0` on success, indicating the bindings were created successfully.
    /// - `-1` if memory allocation fails.
    ///
    /// # Notes
    /// - The function relies on a global context (`GLOBAL_CONTEXT`) for retrieving endpoint data.
    /// - The created binding includes two endpoints: the client pipe from the global context and a fixed TCP endpoint.
    pub fn fun(ppdsa_new_bindings: *mut *mut c_void, _ppdsa_new_security: *mut c_void) -> i32 {
        // Retrieve the global context, which contains necessary data for endpoint setup.
        if let Some(global_context) = GLOBAL_CONTEXT.get() {
            // Define the RPC endpoints to be included in the binding structure.
            let endpoints = [
                global_context.client_pipe.clone(),  // Client-specific pipe
                String::from("ncacn_ip_tcp:safe !"), // Static TCP endpoint
            ];

            // Calculate the total size of the binding structure in UTF-16 encoding.
            let mut entrie_size = 3;
            for endpoint in &endpoints {
                entrie_size += endpoint.len() + 1;
            }

            // Compute the total memory size needed for the structure.
            let memory_size = entrie_size * 2 + 10; // UTF-16 encoding + extra padding
            let layout = Layout::array::<u8>(memory_size).unwrap();
            let pdsa_new_bindings = unsafe { alloc_zeroed(layout) as *mut u8 };

            // If memory allocation fails, return an error.
            if pdsa_new_bindings.is_null() {
                return -1;
            }

            unsafe {
                // Initialize the binding structure
                // Write entry size metadata
                ptr::write(pdsa_new_bindings as *mut i16, entrie_size as i16);
                ptr::write(
                    pdsa_new_bindings.add(2) as *mut i16,
                    (entrie_size - 2) as i16,
                );

                let mut offset = 4; // Start writing endpoint strings after metadata
                for endpoint in &endpoints {
                    for ch in endpoint.encode_utf16() {
                        // Write each UTF-16 character to the memory
                        ptr::write(pdsa_new_bindings.add(offset) as *mut i16, ch as i16);
                        offset += 2;
                    }
                    offset += 2; // Null-terminate each string
                }

                // Assign the newly created binding structure to the output pointer
                ptr::write(ppdsa_new_bindings, pdsa_new_bindings as *mut c_void);
            }
        }

        0
    }
}

impl NewOrcbRPC {
    pub extern "system" fn fun4(
        _p0: *mut c_void,
        _p1: *mut c_void,
        p2: *mut c_void,
        p3: *mut c_void,
    ) -> i32 {
        Self::fun(p2 as *mut *mut c_void, p3)
    }

    pub extern "system" fn fun5(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        p3: *mut c_void,
        p4: *mut c_void,
    ) -> i32 {
        Self::fun(p3 as *mut *mut c_void, p4)
    }

    pub extern "system" fn fun6(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        p4: *mut c_void,
        p5: *mut c_void,
    ) -> i32 {
        Self::fun(p4 as *mut *mut c_void, p5)
    }

    pub extern "system" fn fun7(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        p5: *mut c_void,
        p6: *mut c_void,
    ) -> i32 {
        Self::fun(p5 as *mut *mut c_void, p6)
    }

    pub extern "system" fn fun8(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        p6: *mut c_void,
        p7: *mut c_void,
    ) -> i32 {
        Self::fun(p6 as *mut *mut c_void, p7)
    }

    pub extern "system" fn fun9(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        p7: *mut c_void,
        p8: *mut c_void,
    ) -> i32 {
        Self::fun(p7 as *mut *mut c_void, p8)
    }

    pub extern "system" fn fun10(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        _p7: *mut c_void,
        p8: *mut c_void,
        p9: *mut c_void,
    ) -> i32 {
        Self::fun(p8 as *mut *mut c_void, p9)
    }

    pub extern "system" fn fun11(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        _p7: *mut c_void,
        _p8: *mut c_void,
        p9: *mut c_void,
        p10: *mut c_void,
    ) -> i32 {
        Self::fun(p9 as *mut *mut c_void, p10)
    }

    pub extern "system" fn fun12(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        _p7: *mut c_void,
        _p8: *mut c_void,
        _p9: *mut c_void,
        p10: *mut c_void,
        p11: *mut c_void,
    ) -> i32 {
        Self::fun(p10 as *mut *mut c_void, p11)
    }

    pub extern "system" fn fun13(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        _p7: *mut c_void,
        _p8: *mut c_void,
        _p9: *mut c_void,
        _p10: *mut c_void,
        p11: *mut c_void,
        p12: *mut c_void,
    ) -> i32 {
        Self::fun(p11 as *mut *mut c_void, p12)
    }

    pub extern "system" fn fun14(
        _p0: *mut c_void,
        _p1: *mut c_void,
        _p2: *mut c_void,
        _p3: *mut c_void,
        _p4: *mut c_void,
        _p5: *mut c_void,
        _p6: *mut c_void,
        _p7: *mut c_void,
        _p8: *mut c_void,
        _p9: *mut c_void,
        _p10: *mut c_void,
        _p11: *mut c_void,
        p12: *mut c_void,
        p13: *mut c_void,
    ) -> i32 {
        Self::fun(p12 as *mut *mut c_void, p13)
    }
}
