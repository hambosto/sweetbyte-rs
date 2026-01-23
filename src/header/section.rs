use anyhow::{Result, anyhow, ensure};

use crate::encoding::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Magic = 0,

    Salt = 1,

    HeaderData = 2,

    Metadata = 3,

    Mac = 4,
}

impl SectionType {
    pub const ALL: [Self; 5] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Metadata, Self::Mac];

    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Magic => "Magic",
            Self::Salt => "Salt",
            Self::HeaderData => "HeaderData",
            Self::Metadata => "Metadata",
            Self::Mac => "Mac",
        }
    }
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
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
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn length_u32(&self) -> u32 {
        self.data.len() as u32
    }
}

pub struct Sections {
    sections: [Vec<u8>; 5],
}

impl Sections {
    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        let data = &self.sections[section_type.index()];

        if data.is_empty() { None } else { Some(data) }
    }

    pub fn get_with_min_len(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;

        ensure!(data.len() >= min_len, "{} section too short: expected at least {}, got {}", section_type, min_len, data.len());

        Ok(&data[..min_len])
    }
}

pub struct SectionsBuilder {
    sections: [Option<Vec<u8>>; 5],
}

impl SectionsBuilder {
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        Self { sections: [Some(magic), None, None, None, None] }
    }

    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        self.sections[section_type.index()] = Some(value);

        self
    }

    pub fn build(self) -> Result<Sections> {
        let sections = self
            .sections
            .into_iter()
            .zip(SectionType::ALL)
            .map(|(opt, ty)| {
                let data = opt.ok_or_else(|| anyhow!("{ty} section is missing"))?;
                ensure!(!data.is_empty(), "{ty} section is empty");
                Ok(data)
            })
            .collect::<Result<Vec<Vec<u8>>>>()?
            .try_into()
            .map_err(|_| anyhow!("unexpected section count"))?;

        Ok(Sections { sections })
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

    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        let bytes = length.to_be_bytes();

        self.encode_section(&bytes)
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        ensure!(!section.is_empty(), "invalid encoded section");

        self.encoder.decode(section.data())
    }

    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;

        ensure!(decoded.len() >= 4, "invalid length prefix size");

        Ok(u32::from_be_bytes(decoded[..4].try_into().map_err(|_| anyhow!("length conversion failed"))?))
    }
}
