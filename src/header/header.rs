use crate::utils::UintType;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::mac;
use super::section::SectionType;

pub const MAGIC_BYTES: u32 = 0xCAFEBABE;
pub const MAGIC_SIZE: usize = 4;
pub const MAC_SIZE: usize = 32;
pub const HEADER_DATA_SIZE: usize = 14;
pub const CURRENT_VERSION: u16 = 0x0001;
pub const FLAG_PROTECTED: u32 = 1 << 0;

/// Header represents the metadata prepended to encrypted files.
/// It contains versioning, flags, original file size, and security parameters.
pub struct Header {
    pub version: u16,
    pub flags: u32,
    pub original_size: u64,
    decoded_sections: Option<HashMap<SectionType, Vec<u8>>>,
}

impl Header {
    /// Creates a new default Header.
    pub fn new() -> Result<Self> {
        Ok(Self {
            version: CURRENT_VERSION,
            flags: 0,
            original_size: 0,
            decoded_sections: None,
        })
    }

    pub fn get_original_size(&self) -> Result<i64> {
        if self.original_size > i64::MAX as u64 {
            return Err(anyhow!("original size overflow during i64 conversion"));
        }
        Ok(self.original_size as i64)
    }

    pub fn set_original_size(&mut self, size: u64) {
        self.original_size = size;
    }

    pub fn is_protected(&self) -> bool {
        self.flags & FLAG_PROTECTED != 0
    }

    pub fn set_protected(&mut self, protected: bool) {
        if protected {
            self.flags |= FLAG_PROTECTED;
        } else {
            self.flags &= !FLAG_PROTECTED;
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version > CURRENT_VERSION {
            return Err(anyhow!(
                "unsupported version: {} (current: {})",
                self.version,
                CURRENT_VERSION
            ));
        }
        if self.original_size == 0 {
            return Err(anyhow!("original size cannot be zero"));
        }
        Ok(())
    }

    pub fn marshal(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let serializer = super::serializer::Serializer::new(self)?;
        serializer.marshal(salt, key)
    }

    pub fn unmarshal(&mut self, reader: &mut dyn std::io::Read) -> Result<()> {
        let mut deserializer = super::deserializer::Deserializer::new(self)?;
        deserializer.unmarshal(reader)
    }

    pub fn salt(&self) -> Result<Vec<u8>> {
        self.section(SectionType::Salt, crate::crypto::ARGON_SALT_LEN)
    }

    #[allow(dead_code)]
    pub fn magic(&self) -> Result<Vec<u8>> {
        self.section(SectionType::Magic, MAGIC_SIZE)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        if key.is_empty() {
            return Err(anyhow!("key cannot be empty"));
        }

        let expected_mac = self.section(SectionType::MAC, MAC_SIZE)?;
        let magic = self.section(SectionType::Magic, MAGIC_SIZE)?;
        let salt = self.section(SectionType::Salt, crate::crypto::ARGON_SALT_LEN)?;
        let header_data = self.section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

        mac::verify_mac(key, &expected_mac, &[&magic, &salt, &header_data])
    }

    fn section(&self, st: SectionType, min_len: usize) -> Result<Vec<u8>> {
        let sections = self
            .decoded_sections
            .as_ref()
            .ok_or_else(|| anyhow!("header not unmarshalled yet"))?;

        let data = sections
            .get(&st)
            .ok_or_else(|| anyhow!("required section missing"))?;

        if data.len() < min_len {
            return Err(anyhow!("section too short"));
        }

        Ok(data[..min_len].to_vec())
    }

    pub(super) fn set_decoded_sections(&mut self, sections: HashMap<SectionType, Vec<u8>>) {
        self.decoded_sections = Some(sections);
    }

    pub(super) fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_DATA_SIZE);
        data.extend_from_slice(&self.version.to_bytes());
        data.extend_from_slice(&self.flags.to_bytes());
        data.extend_from_slice(&self.original_size.to_bytes());
        data
    }

    pub(super) fn deserialize(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != HEADER_DATA_SIZE {
            return Err(anyhow!(
                "invalid header data size: expected {} bytes, got {}",
                HEADER_DATA_SIZE,
                data.len()
            ));
        }

        self.version = u16::from_bytes(&data[0..2]);
        self.flags = u32::from_bytes(&data[2..6]);
        self.original_size = u64::from_bytes(&data[6..14]);
        Ok(())
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new().expect("Failed to create default header")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_flags() {
        let mut h = Header::new().unwrap();
        assert!(!h.is_protected());

        h.set_protected(true);
        assert!(h.is_protected());

        h.set_protected(false);
        assert!(!h.is_protected());
    }

    #[test]
    fn test_header_serialize_deserialize() {
        let mut h = Header::new().unwrap();
        h.set_original_size(123456);
        h.set_protected(true);

        let serialized = h.serialize();
        assert_eq!(serialized.len(), HEADER_DATA_SIZE);

        let mut h2 = Header::new().unwrap();
        h2.deserialize(&serialized).unwrap();

        assert_eq!(h.version, h2.version);
        assert_eq!(h.flags, h2.flags);
        assert_eq!(h.original_size, h2.original_size);
    }
}
