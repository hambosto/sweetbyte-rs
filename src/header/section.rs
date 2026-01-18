use anyhow::{Result, anyhow, bail};

use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Magic,
    Salt,
    HeaderData,
    Mac,
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Magic => write!(f, "Magic"),
            Self::Salt => write!(f, "Salt"),
            Self::HeaderData => write!(f, "HeaderData"),
            Self::Mac => write!(f, "Mac"),
        }
    }
}

pub(crate) const SECTION_ORDER: [SectionType; 4] = [SectionType::Magic, SectionType::Salt, SectionType::HeaderData, SectionType::Mac];

#[derive(Debug)]
pub struct EncodedSection {
    data: Vec<u8>,
    length: u32,
}

impl EncodedSection {
    #[inline]
    pub fn new(data: Vec<u8>, length: u32) -> Self {
        Self { data, length }
    }

    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    #[must_use]
    pub fn length(&self) -> u32 {
        self.length
    }
}

#[derive(Debug, Default)]
pub struct Sections {
    magic: Vec<u8>,
    salt: Vec<u8>,
    header_data: Vec<u8>,
    mac: Vec<u8>,
}

impl Sections {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, section_type: SectionType, data: Vec<u8>) {
        match section_type {
            SectionType::Magic => self.magic = data,
            SectionType::Salt => self.salt = data,
            SectionType::HeaderData => self.header_data = data,
            SectionType::Mac => self.mac = data,
        }
    }

    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        let data = match section_type {
            SectionType::Magic => &self.magic,
            SectionType::Salt => &self.salt,
            SectionType::HeaderData => &self.header_data,
            SectionType::Mac => &self.mac,
        };
        if data.is_empty() { None } else { Some(data) }
    }

    pub fn get_with_min_len(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{} section not found", section_type))?;

        if data.len() < min_len {
            bail!("{} section too short: expected {}, got {}", section_type, min_len, data.len());
        }

        Ok(&data[..min_len])
    }
}

pub struct SectionEncoder {
    reed_solomon: Encoding,
}

impl SectionEncoder {
    pub fn new() -> Result<Self> {
        let reed_solomon = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        Ok(Self { reed_solomon })
    }

    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let encoded = self.reed_solomon.encode(data)?;
        let length = encoded.len() as u32;

        Ok(EncodedSection::new(encoded, length))
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        if section.data.is_empty() {
            bail!("invalid encoded section");
        }

        self.reed_solomon.decode(&section.data)
    }

    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        self.encode_section(&length.to_be_bytes())
    }

    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        if decoded.len() < 4 {
            bail!("invalid length prefix size");
        }

        let bytes: [u8; 4] = decoded[..4].try_into().map_err(|_| anyhow!("slice length verified"))?;
        Ok(u32::from_be_bytes(bytes))
    }
}
