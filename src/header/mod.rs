use std::io::Read;

use anyhow::{Context, Result, bail};

use crate::config::{ARGON_SALT_LEN, CURRENT_VERSION, FLAG_PROTECTED, HEADER_DATA_SIZE, MAC_SIZE, MAGIC_SIZE};
use crate::header::deserializer::Deserializer;
use crate::header::mac::Mac;
use crate::header::section::{SectionType, Sections};
use crate::header::serializer::Serializer;

pub mod deserializer;
pub mod mac;
pub mod section;
pub mod serializer;

#[derive(Debug)]
pub struct Header {
    original_size: u64,
    flags: u32,
    version: u16,
    sections: Option<Sections>,
}

impl Header {
    #[inline]
    pub fn new() -> Self {
        Self { original_size: 0, flags: 0, version: CURRENT_VERSION, sections: None }
    }

    #[inline]
    #[must_use]
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    #[inline]
    pub fn set_original_size(&mut self, size: u64) {
        self.original_size = size;
    }

    #[inline]
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    #[inline]
    pub(crate) fn set_version(&mut self, version: u16) {
        self.version = version;
    }

    #[inline]
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    #[inline]
    pub(crate) fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    #[inline]
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.flags & FLAG_PROTECTED != 0
    }

    #[inline]
    pub fn set_protected(&mut self, protected: bool) {
        if protected {
            self.flags |= FLAG_PROTECTED;
        } else {
            self.flags &= !FLAG_PROTECTED;
        }
    }

    #[inline]
    pub(crate) fn set_sections(&mut self, sections: Sections) {
        self.sections = Some(sections);
    }

    pub fn validate(&self) -> Result<()> {
        if self.version > CURRENT_VERSION {
            bail!("unsupported version: {} (current: {})", self.version, CURRENT_VERSION);
        }

        if self.original_size == 0 {
            bail!("original size cannot be zero");
        }

        Ok(())
    }

    pub fn marshal(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let serializer = Serializer::new(self)?;
        serializer.marshal(salt, key)
    }

    pub fn unmarshal<R: Read>(&mut self, reader: R) -> Result<()> {
        let mut deserializer = Deserializer::new(self)?;
        deserializer.unmarshal(reader)
    }

    pub fn salt(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Salt, ARGON_SALT_LEN)
    }

    pub fn magic(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Magic, MAGIC_SIZE)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        if key.is_empty() {
            bail!("key cannot be empty");
        }

        let expected_mac = self.get_section(SectionType::Mac, MAC_SIZE)?;
        let magic = self.get_section(SectionType::Magic, MAGIC_SIZE)?;
        let salt = self.get_section(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = self.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

        Mac::verify_bytes(key, expected_mac, &[magic, salt, header_data])
    }

    pub(crate) fn get_section(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        let sections = self.sections.as_ref().context("header not unmarshalled yet")?;
        sections.get_with_min_len(section_type, min_len)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::cipher::{derive_key, random_bytes};

    #[test]
    fn header_new_has_correct_defaults() {
        let header = Header::new();
        assert_eq!(header.version(), CURRENT_VERSION);
        assert_eq!(header.flags(), 0);
        assert_eq!(header.original_size(), 0);
    }

    #[test]
    fn header_protected_flag_toggles() {
        let mut header = Header::new();
        assert!(!header.is_protected());

        header.set_protected(true);
        assert!(header.is_protected());

        header.set_protected(false);
        assert!(!header.is_protected());
    }

    #[test]
    fn header_marshal_unmarshal_roundtrip() {
        let salt: [u8; ARGON_SALT_LEN] = random_bytes().unwrap();
        let key = derive_key(b"password", &salt).unwrap();

        let mut header = Header::new();
        header.set_original_size(12345);
        header.set_protected(true);

        let serialized = header.marshal(&salt, &key).unwrap();
        let mut new_header = Header::new();
        new_header.unmarshal(Cursor::new(&serialized)).unwrap();

        assert_eq!(new_header.version(), header.version());
        assert_eq!(new_header.flags(), header.flags());
        assert_eq!(new_header.original_size(), header.original_size());
    }

    #[test]
    fn header_verify_succeeds_with_correct_key() {
        let salt: [u8; ARGON_SALT_LEN] = random_bytes().unwrap();
        let key = derive_key(b"password", &salt).unwrap();
        let mut header = Header::new();

        header.set_original_size(12345);
        header.set_protected(true);

        let serialized = header.marshal(&salt, &key).unwrap();
        let mut new_header = Header::new();
        new_header.unmarshal(Cursor::new(&serialized)).unwrap();

        assert!(new_header.verify(&key).is_ok());
    }

    #[test]
    fn header_verify_fails_with_wrong_key() {
        let salt: [u8; ARGON_SALT_LEN] = random_bytes().unwrap();
        let key = derive_key(b"password", &salt).unwrap();
        let wrong_key = derive_key(b"wrong_password", &salt).unwrap();

        let mut header = Header::new();
        header.set_original_size(12345);
        header.set_protected(true);

        let serialized = header.marshal(&salt, &key).unwrap();

        let mut new_header = Header::new();
        new_header.unmarshal(Cursor::new(&serialized)).unwrap();

        assert!(new_header.verify(&wrong_key).is_err());
    }
}
