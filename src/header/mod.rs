use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{ARGON_SALT_LEN, CURRENT_VERSION, DATA_SHARDS, FLAG_PROTECTED, HEADER_DATA_SIZE, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS};
use crate::header::deserializer::{Deserializer, ParsedHeaderData};
use crate::header::mac::Mac;
use crate::header::section::{SectionEncoder, SectionType, Sections};
use crate::header::serializer::Serializer;

pub mod deserializer;
pub mod mac;
pub mod section;
pub mod serializer;

pub struct Header {
    encoder: SectionEncoder,
    version: u16,
    flags: u32,
    original_size: u64,
    sections: Option<Sections>,
}

impl Header {
    pub fn new(version: u16, original_size: u64, flags: u32) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        Ok(Self { encoder, version, original_size, flags, sections: None })
    }

    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let deserializer = Deserializer::new(&encoder);
        let parsed = deserializer.deserialize(reader)?;

        Self::from_parsed_data(parsed, encoder)
    }

    #[inline]
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version >= 1 && self.version <= CURRENT_VERSION, "unsupported version: {} (valid: 1-{}", self.version, CURRENT_VERSION);
        ensure!(self.original_size != 0, "original size cannot be zero");
        ensure!(self.flags & FLAG_PROTECTED != 0, "file is not protected");

        Ok(())
    }

    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;

        let serializer = Serializer::new(&self.encoder);
        serializer.serialize(self.version, self.flags, self.original_size, salt, key)
    }

    pub fn salt(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Salt, ARGON_SALT_LEN)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "key cannot be empty");

        let expected_mac = self.get_section(SectionType::Mac, MAC_SIZE)?;
        let magic = self.get_section(SectionType::Magic, MAGIC_SIZE)?;
        let salt = self.get_section(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = self.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

        Mac::new(key)?.verify(expected_mac, &[magic, salt, header_data])
    }

    fn from_parsed_data(data: ParsedHeaderData, encoder: SectionEncoder) -> Result<Self> {
        let header = Self { encoder, version: data.version(), flags: data.flags(), original_size: data.original_size(), sections: Some(data.into_sections()) };

        header.validate()?;
        Ok(header)
    }

    fn get_section(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        self.sections.as_ref().context("header not deserialized yet")?.get_with_min_len(section_type, min_len)
    }
}
