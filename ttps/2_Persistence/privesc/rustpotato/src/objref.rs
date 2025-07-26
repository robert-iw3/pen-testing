use crate::{_print, def::TowerProtocol, utils::GUID};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
/// Represents the type of an OBJREF structure.
pub enum ObjRefType {
    Standard = 0x1,
    Handler = 0x2,
    Custom = 0x4,
}

/// Represents an OBJREF structure with GUID and standard object reference details.
pub struct ObjRef {
    pub guid: GUID,
    pub standard_objref: Standard,
}

impl ObjRef {
    const SIGNATURE: u32 = 0x574f454d;

    /// Creates a new instance of `ObjRef`.
    pub fn new(guid: GUID, standard_objref: Standard) -> Self {
        ObjRef {
            guid,
            standard_objref,
        }
    }

    /// Parses an OBJREF structure from a byte stream.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor::new(bytes);

        // Validate OBJREF signature.
        let signature = cursor.read_u32::<byteorder::LittleEndian>().ok()?;
        if signature != Self::SIGNATURE {
            _print!("[-] Invalid OBJREF signature");
            return None;
        }

        let flags = cursor.read_u32::<byteorder::LittleEndian>().ok()?;
        let mut guid_buf = [0u8; 16];
        cursor.read_exact(&mut guid_buf).ok()?;
        let guid = GUID::from_bytes(&guid_buf).ok()?;

        _print!("[+] DCOM object GUID: {}", guid.value);

        // Handle only Standard OBJREF type.
        if flags & ObjRefType::Standard as u32 != 0 {
            let standard_objref = Standard::from_reader(&mut cursor)?;
            Some(ObjRef {
                guid,
                standard_objref,
            })
        } else {
            _print!("[-] Unsupported OBJREF type");
            None
        }
    }

    /// Serializes the OBJREF structure into bytes.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = vec![];
        bytes
            .write_u32::<byteorder::LittleEndian>(Self::SIGNATURE)
            .ok()?;
        bytes
            .write_u32::<byteorder::LittleEndian>(ObjRefType::Standard as u32)
            .ok()?;
        bytes.extend_from_slice(&self.guid.to_le_bytes().ok()?);
        self.standard_objref.save(&mut bytes)?;
        Some(bytes)
    }
}

/// Represents a security binding in the OBJREF structure.
#[derive(Clone, Default)]
pub struct SecurityBinding {
    pub authn_svc: u16,
    pub authz_svc: u16,
    pub principal_name: Option<String>,
}

impl SecurityBinding {
    /// Creates a new instance of `SecurityBinding`.
    pub fn new(authn_svc: u16, authz_svc: u16, principal_name: Option<String>) -> Self {
        SecurityBinding {
            authn_svc,
            authz_svc,
            principal_name,
        }
    }

    /// Reads a `SecurityBinding` structure from a byte stream.
    fn from_reader<R: Read>(reader: &mut R) -> Option<Self> {
        let authn_svc = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        let authz_svc = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        let principal_name = read_string(reader);
        Some(SecurityBinding {
            authn_svc,
            authz_svc,
            principal_name,
        })
    }

    /// Serializes the `SecurityBinding` structure into bytes.
    fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = vec![];
        bytes
            .write_u16::<byteorder::LittleEndian>(self.authn_svc)
            .ok()?;
        bytes
            .write_u16::<byteorder::LittleEndian>(self.authz_svc)
            .ok()?;
        if let Some(principal_name) = &self.principal_name {
            bytes.extend(
                principal_name
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<u8>>(),
            );
        }
        bytes.extend_from_slice(&(0u16.to_le_bytes()));
        bytes.extend_from_slice(&(0u16.to_le_bytes()));
        Some(bytes)
    }
}

/// Represents a string binding in the OBJREF structure.
#[derive(Clone)]
pub struct StringBinding {
    pub tower_id: TowerProtocol,
    pub network_address: String,
}

impl StringBinding {
    /// Reads a `StringBinding` structure from a byte stream.
    pub fn from_reader<R: Read>(reader: &mut R) -> Option<Self> {
        let tower_id = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        let network_address = read_string(reader)?;
        Some(StringBinding {
            tower_id: TowerProtocol::try_from(tower_id).ok()?,
            network_address,
        })
    }

    /// Serializes the `StringBinding` structure into bytes.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = vec![];
        bytes
            .write_u16::<byteorder::LittleEndian>(self.tower_id as u16)
            .ok()?;
        bytes.extend(
            self.network_address
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );
        bytes.extend_from_slice(&(0u16.to_le_bytes()));
        bytes.extend_from_slice(&(0u16.to_le_bytes()));
        Some(bytes)
    }
}

/// Represents a dual string array in the OBJREF structure.
#[derive(Clone)]
#[allow(unused)]
pub struct DualStringArray {
    pub num_entries: u16,
    pub security_offset: u16,
    pub string_binding: StringBinding,
    pub security_binding: SecurityBinding,
}

impl DualStringArray {
    /// Reads a `DualStringArray` structure from a byte stream.
    pub fn from_reader<R: Read>(reader: &mut R) -> Option<Self> {
        let num_entries = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        let security_offset = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        let string_binding = StringBinding::from_reader(reader)?;
        let security_binding = SecurityBinding::from_reader(reader)?;
        Some(DualStringArray {
            num_entries,
            security_offset,
            string_binding,
            security_binding,
        })
    }

    /// Serializes the `DualStringArray` structure into a writer.
    pub fn save<W: Write>(&self, writer: &mut W) -> Option<()> {
        let string_binding_bytes = self.string_binding.to_bytes()?;
        let security_binding_bytes = self.security_binding.to_bytes()?;
        let num_entries = (string_binding_bytes.len() + security_binding_bytes.len()) as u16 / 2;
        let security_offset = string_binding_bytes.len() as u16 / 2;

        writer
            .write_u16::<byteorder::LittleEndian>(num_entries)
            .ok()?;
        writer
            .write_u16::<byteorder::LittleEndian>(security_offset)
            .ok()?;
        writer.write_all(&string_binding_bytes).ok()?;
        writer.write_all(&security_binding_bytes).ok()?;
        Some(())
    }
}

/// Represents the standard structure within an OBJREF.
#[derive(Clone)]
pub struct Standard {
    pub flags: u32,
    pub public_refs: u32,
    pub oxid: u64,
    pub oid: u64,
    pub ipid: GUID,
    pub dual_string_array: DualStringArray,
}

impl Standard {
    /// Reads a `Standard` structure from a byte stream.
    pub fn from_reader<R: Read>(reader: &mut R) -> Option<Self> {
        let flags = reader.read_u32::<byteorder::LittleEndian>().ok()?;
        let public_refs = reader.read_u32::<byteorder::LittleEndian>().ok()?;
        let oxid = reader.read_u64::<byteorder::LittleEndian>().ok()?;
        let oid = reader.read_u64::<byteorder::LittleEndian>().ok()?;
        let mut buf = vec![0u8; 16];
        reader.read_exact(&mut buf).ok()?;
        let ipid = GUID::from_bytes(&buf).ok()?;
        let dual_string_array = DualStringArray::from_reader(reader)?;

        _print!("[+] DCOM object IPID: {}", ipid.value);
        _print!("[+] DCOM object OXID: 0x{:x}", oxid);
        _print!("[+] DCOM object OID: 0x{:x}", oid);
        _print!("[+] DCOM object Flags: 0x{:x}", flags);
        _print!("[+] DCOM object PublicRefs: {}", public_refs);

        Some(Standard {
            flags,
            public_refs,
            oxid,
            oid,
            ipid,
            dual_string_array,
        })
    }

    /// Serializes the `Standard` structure into a writer.
    fn save<W: Write>(&self, writer: &mut W) -> Option<()> {
        writer
            .write_u32::<byteorder::LittleEndian>(self.flags)
            .ok()?;
        writer
            .write_u32::<byteorder::LittleEndian>(self.public_refs)
            .ok()?;
        writer
            .write_u64::<byteorder::LittleEndian>(self.oxid)
            .ok()?;
        writer.write_u64::<byteorder::LittleEndian>(self.oid).ok()?;
        writer.write_all(&self.ipid.to_le_bytes().ok()?).ok()?;
        self.dual_string_array.save(writer)?;
        Some(())
    }
}

/// Reads a UTF-16 string from a byte stream.
fn read_string(reader: &mut impl Read) -> Option<String> {
    let mut result_str = String::new();
    loop {
        let character = reader.read_u16::<byteorder::LittleEndian>().ok()?;
        if character == 0 {
            reader.read_u16::<byteorder::LittleEndian>().ok()?; // Skip padding
            break;
        }
        result_str.push(char::from_u32(character as u32).unwrap_or('?'));
    }
    Some(result_str)
}
