//! Core header metadata and data structures.
//!
//! This module defines the `Header` struct which represents the metadata
//! prepended to encrypted files, including versioning, flags, and original file size.

use anyhow::{Result, anyhow};
use std::collections::HashMap;

use super::encoding::SectionType;
use crate::utils::UintType;

/// Magic bytes identifying a SweetByte encrypted file
pub const MAGIC_BYTES: u32 = 0xCAFEBABE;

/// Size of magic bytes in the header
pub const MAGIC_SIZE: usize = 4;

/// Size of MAC (HMAC-SHA256) in bytes
pub const MAC_SIZE: usize = 32;

/// Size of the serialized header data (version + flags + original_size)
pub const HEADER_DATA_SIZE: usize = 14;

/// Current header format version
pub const CURRENT_VERSION: u16 = 0x0001;

/// Flag indicating the file is protected/encrypted
pub const FLAG_PROTECTED: u32 = 1 << 0;

/// Header represents the metadata prepended to encrypted files.
///
/// It contains versioning information, flags indicating the file state,
/// the original unencrypted file size, and decoded sections after unmarshaling.
#[derive(Debug)]
pub struct Header {
    /// Header format version
    pub version: u16,

    /// Bit flags for file state (e.g., FLAG_PROTECTED)
    pub flags: u32,

    /// Original size of the unencrypted file in bytes
    pub original_size: u64,

    /// Decoded header sections (populated after unmarshaling)
    pub(super) decoded_sections: Option<HashMap<SectionType, Vec<u8>>>,
}

impl Header {
    /// Creates a new default Header with current version.
    pub fn new() -> Result<Self> {
        Ok(Self {
            version: CURRENT_VERSION,
            flags: 0,
            original_size: 0,
            decoded_sections: None,
        })
    }

    /// Gets the original file size as i64.
    ///
    /// # Errors
    ///
    /// Returns an error if the size exceeds i64::MAX.
    pub fn get_original_size(&self) -> Result<i64> {
        if self.original_size > i64::MAX as u64 {
            return Err(anyhow!("original size overflow during i64 conversion"));
        }
        Ok(self.original_size as i64)
    }

    /// Sets the original file size.
    pub fn set_original_size(&mut self, size: u64) {
        self.original_size = size;
    }

    /// Checks if the file is marked as protected/encrypted.
    pub fn is_protected(&self) -> bool {
        self.flags & FLAG_PROTECTED != 0
    }

    /// Sets or clears the protected flag.
    pub fn set_protected(&mut self, protected: bool) {
        if protected {
            self.flags |= FLAG_PROTECTED;
        } else {
            self.flags &= !FLAG_PROTECTED;
        }
    }

    /// Validates the header for correctness.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Version is newer than CURRENT_VERSION
    /// - Original size is zero
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

    /// Retrieves the salt from decoded sections.
    ///
    /// # Errors
    ///
    /// Returns an error if header hasn't been unmarshaled or salt is missing.
    pub fn salt(&self) -> Result<Vec<u8>> {
        self.section(SectionType::Salt, crate::crypto::ARGON_SALT_LEN)
    }

    /// Retrieves the magic bytes from decoded sections.
    #[allow(dead_code)]
    pub fn magic(&self) -> Result<Vec<u8>> {
        self.section(SectionType::Magic, MAGIC_SIZE)
    }

    /// Retrieves a specific section with minimum length validation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Header hasn't been unmarshaled
    /// - Section is missing
    /// - Section is shorter than min_len
    pub(super) fn section(&self, st: SectionType, min_len: usize) -> Result<Vec<u8>> {
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

    /// Sets the decoded sections (used by io module after unmarshaling).
    pub(super) fn set_decoded_sections(&mut self, sections: HashMap<SectionType, Vec<u8>>) {
        self.decoded_sections = Some(sections);
    }

    /// Serializes header metadata to bytes.
    ///
    /// Returns a 14-byte array: version (2) + flags (4) + original_size (8)
    pub(super) fn serialize_metadata(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_DATA_SIZE);
        data.extend_from_slice(&self.version.to_bytes());
        data.extend_from_slice(&self.flags.to_bytes());
        data.extend_from_slice(&self.original_size.to_bytes());
        data
    }

    /// Deserializes header metadata from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if data is not exactly HEADER_DATA_SIZE bytes.
    pub(super) fn deserialize_metadata(&mut self, data: &[u8]) -> Result<()> {
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

        let serialized = h.serialize_metadata();
        assert_eq!(serialized.len(), HEADER_DATA_SIZE);

        let mut h2 = Header::new().unwrap();
        h2.deserialize_metadata(&serialized).unwrap();

        assert_eq!(h.version, h2.version);
        assert_eq!(h.flags, h2.flags);
        assert_eq!(h.original_size, h2.original_size);
    }
}
