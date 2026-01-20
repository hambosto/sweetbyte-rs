use anyhow::{Result, anyhow, ensure};

use crate::encoding::Encoding;

pub const SECTION_COUNT: usize = 4;
const MAX_SECTION_SIZE: u32 = 1 << 24;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SectionType {
    Magic = 0,
    Salt = 1,
    HeaderData = 2,
    Mac = 3,
}

impl SectionType {
    pub const ALL: [Self; SECTION_COUNT] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Mac];

    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
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

#[derive(Debug, Clone)]
pub struct EncodedSection {
    data: Vec<u8>,
}

impl EncodedSection {
    #[inline]
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    #[must_use]
    pub fn length(&self) -> u32 {
        self.data.len() as u32
    }
}

#[derive(Debug, Clone)]
pub struct Sections {
    magic: Vec<u8>,
    salt: Vec<u8>,
    header_data: Vec<u8>,
    mac: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum LengthCheck {
    Exact(usize),
    Min(usize),
}

impl Sections {
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

    pub fn get_len(&self, section_type: SectionType, check: LengthCheck) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;

        match check {
            LengthCheck::Exact(expected) => {
                ensure!(data.len() == expected, "{} section wrong size: expected {}, got {}", section_type, expected, data.len());
                Ok(data)
            }
            LengthCheck::Min(min) => {
                ensure!(data.len() >= min, "{} section too small: expected at least {}, got {}", section_type, min, data.len());
                Ok(&data[..min])
            }
        }
    }
}

#[derive(Debug)]
pub struct SectionsBuilder {
    magic: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    header_data: Option<Vec<u8>>,
    mac: Option<Vec<u8>>,
}

impl SectionsBuilder {
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        Self { magic: Some(magic), salt: None, header_data: None, mac: None }
    }

    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        match section_type {
            SectionType::Magic => self.magic = Some(value),
            SectionType::Salt => self.salt = Some(value),
            SectionType::HeaderData => self.header_data = Some(value),
            SectionType::Mac => self.mac = Some(value),
        }
        self
    }

    pub fn build(self) -> Result<Sections> {
        let sections = [("Magic", self.magic), ("Salt", self.salt), ("HeaderData", self.header_data), ("Mac", self.mac)];

        let mut validated: Vec<Vec<u8>> = Vec::with_capacity(SECTION_COUNT);
        for (name, section) in sections {
            let data = section.ok_or_else(|| anyhow!("{name} section is missing"))?;
            ensure!(!data.is_empty(), "{name} section is empty");
            validated.push(data);
        }

        let [magic, salt, header_data, mac]: [Vec<u8>; 4] = validated.try_into().map_err(|_| anyhow!("unexpected section count"))?;
        Ok(Sections { magic, salt, header_data, mac })
    }
}

pub struct SectionEncoder {
    encoder: Encoding,
}

impl SectionEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        ensure!(!data.is_empty(), "data cannot be empty");

        let encoded = self.encoder.encode(data)?;

        Ok(EncodedSection::new(encoded))
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        ensure!(!section.data.is_empty(), "invalid encoded section");

        self.encoder.decode(&section.data)
    }

    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        self.encode_section(&length.to_be_bytes())
    }

    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        let bytes: [u8; 4] = decoded[..4].try_into().map_err(|_| anyhow!("length conversion failed"))?;
        let length = u32::from_be_bytes(bytes);

        ensure!(length <= MAX_SECTION_SIZE, "section size {length} exceeds maximum {MAX_SECTION_SIZE}");

        Ok(length)
    }
}
