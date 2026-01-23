use std::io::Read;

use anyhow::{Context, Result, anyhow, ensure};
use hashbrown::HashMap;

use crate::{config::MAGIC_BYTES, encoding::Encoding};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Magic = 0,
    Salt = 1,
    HeaderData = 2,
    Metadata = 3,
    Mac = 4,
}

impl SectionType {
    pub const ALL: [Self; 5] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Metadata, Self::Mac];

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
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.data.len() as u32
    }
}

pub struct Sections {
    sections: HashMap<SectionType, Vec<u8>>,
}

impl Sections {
    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        self.sections.get(&section_type).filter(|d| !d.is_empty()).map(|d| d.as_slice())
    }

    pub fn get_with_min_len(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;
        ensure!(data.len() >= min_len, "{} section too short: expected at least {}, got {}", section_type, min_len, data.len());

        Ok(&data[..min_len])
    }
}

pub struct SectionsBuilder {
    sections: HashMap<SectionType, Vec<u8>>,
}

impl SectionsBuilder {
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        let mut sections = HashMap::new();
        sections.insert(SectionType::Magic, magic);
        Self { sections }
    }

    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        self.sections.insert(section_type, value);
        self
    }

    pub fn build(self) -> Result<Sections> {
        for &ty in &SectionType::ALL {
            let data = self.sections.get(&ty).ok_or_else(|| anyhow!("{ty} section is missing"))?;
            ensure!(!data.is_empty(), "{ty} section is empty");
        }
        Ok(Sections { sections: self.sections })
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
        self.encode_section(&length.to_be_bytes())
    }

    pub fn encode_sections_and_lengths(&self, raw_sections: &[&[u8]; 5]) -> Result<(Vec<EncodedSection>, Vec<EncodedSection>)> {
        let sections: Vec<EncodedSection> = raw_sections.iter().map(|data| self.encode_section(data)).collect::<Result<Vec<EncodedSection>>>()?;
        let length_sections: Vec<EncodedSection> = sections.iter().map(|section| self.encode_length(section.len())).collect::<Result<Vec<EncodedSection>>>()?;
        Ok((sections, length_sections))
    }

    pub fn build_lengths_header(length_sections: &[EncodedSection]) -> [u8; 20] {
        let mut header = [0u8; 20];
        for (i, section) in length_sections.iter().enumerate() {
            let offset = i * 4;
            header[offset..offset + 4].copy_from_slice(&section.len().to_be_bytes());
        }
        header
    }
}

pub struct SectionDecoder {
    encoder: Encoding,
}

impl SectionDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        ensure!(!section.is_empty(), "invalid encoded section");
        self.encoder.decode(section.data())
    }

    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        decoded[..4].try_into().map(u32::from_be_bytes).map_err(|_| anyhow!("length conversion failed"))
    }

    pub fn read_lengths_header<R: Read>(&self, reader: &mut R) -> Result<[u32; 5]> {
        let mut header = [0u8; 20];
        reader.read_exact(&mut header).context("failed to read lengths header")?;

        let mut result = [0u32; 5];
        for (i, slot) in result.iter_mut().enumerate() {
            let offset = i * 4;
            let bytes: [u8; 4] = header[offset..offset + 4].try_into()?;
            *slot = u32::from_be_bytes(bytes);
        }
        Ok(result)
    }

    pub fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; 5]) -> Result<[u32; 5]> {
        let mut result = [0u32; 5];
        for (i, (&section_type, &size)) in SectionType::ALL.iter().zip(length_sizes).enumerate() {
            let encoded = self.read_exact(reader, size as usize, || format!("failed to read encoded length for {section_type}"))?;
            result[i] = self.decode_length(&EncodedSection::new(encoded))?;
        }
        Ok(result)
    }

    pub fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 5]) -> Result<Sections> {
        let encoded = self.read_exact(reader, section_lengths[0] as usize, || format!("failed to read encoded {}", SectionType::Magic))?;
        let magic = self.decode_section(&EncodedSection::new(encoded))?;
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes: expected {:?}, got {:?}", MAGIC_BYTES.to_be_bytes(), magic);

        let mut builder = SectionsBuilder::with_magic(magic);
        for (&section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let encoded = self.read_exact(reader, length as usize, || format!("failed to read encoded {section_type}"))?;
            let decoded = self.decode_section(&EncodedSection::new(encoded))?;
            builder.set(section_type, decoded);
        }

        builder.build()
    }

    fn read_exact<R: Read, F>(&self, reader: &mut R, size: usize, context_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> String,
    {
        let mut buffer = vec![0u8; size];
        reader.read_exact(&mut buffer).with_context(context_fn)?;
        Ok(buffer)
    }
}
