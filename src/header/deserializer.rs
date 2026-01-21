use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::section::{EncodedSection, SectionEncoder, SectionType, Sections, SectionsBuilder};

pub struct ParsedHeaderData {
    version: u16,

    flags: u32,

    original_size: u64,

    sections: Sections,
}

impl ParsedHeaderData {
    #[inline]
    pub(crate) fn new(version: u16, flags: u32, original_size: u64, sections: Sections) -> Self {
        Self { version, flags, original_size, sections }
    }

    #[inline]
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    #[inline]
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    #[inline]
    #[must_use]
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    #[inline]
    pub fn into_sections(self) -> Sections {
        self.sections
    }
}

pub struct Deserializer<'a> {
    encoder: &'a SectionEncoder,
}

impl<'a> Deserializer<'a> {
    #[inline]
    #[must_use]
    pub fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<ParsedHeaderData> {
        let length_sizes = Self::read_lengths_header(&mut reader)?;

        let section_lengths = self.read_and_decode_lengths(&mut reader, &length_sizes)?;

        let sections = self.read_and_decode_sections(&mut reader, &section_lengths)?;

        let magic = sections.get_with_min_len(SectionType::Magic, MAGIC_SIZE)?;
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes");

        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow::anyhow!("HeaderData section not found"))?;
        let (version, flags, original_size) = Self::parse_header_data(header_data)?;

        Ok(ParsedHeaderData::new(version, flags, original_size, sections))
    }

    fn read_lengths_header<R: Read>(reader: &mut R) -> Result<[u32; 4]> {
        let header = Self::read_exact::<16, R>(reader).context("failed to read lengths header")?;

        Ok([
            u32::from_be_bytes(header[0..4].try_into().context("magic length conversion")?),
            u32::from_be_bytes(header[4..8].try_into().context("salt length conversion")?),
            u32::from_be_bytes(header[8..12].try_into().context("header data length conversion")?),
            u32::from_be_bytes(header[12..16].try_into().context("mac length conversion")?),
        ])
    }

    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; 4]) -> Result<[u32; 4]> {
        let mut result = [0u32; 4];

        for (i, &size) in length_sizes.iter().enumerate() {
            let section_type = SectionType::ALL[i];

            let mut encoded = vec![0u8; size as usize];

            reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded length for {section_type}"))?;

            let section = EncodedSection::new(encoded);
            result[i] = self.encoder.decode_length(&section)?;
        }

        Ok(result)
    }

    fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 4]) -> Result<Sections> {
        let magic = self.read_section(reader, SectionType::Magic, section_lengths[0])?;

        let mut builder = SectionsBuilder::with_magic(magic);

        for (section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let decoded = self.read_section(reader, *section_type, length)?;

            builder.set(*section_type, decoded);
        }

        builder.build()
    }

    fn read_section<R: Read>(&self, reader: &mut R, section_type: SectionType, length: u32) -> Result<Vec<u8>> {
        let mut encoded = vec![0u8; length as usize];

        reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded {section_type}"))?;

        let section = EncodedSection::new(encoded);
        self.encoder.decode_section(&section)
    }

    fn parse_header_data(data: &[u8]) -> Result<(u16, u32, u64)> {
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);

        let flags = u32::from_be_bytes(data[2..6].try_into().context("flags conversion")?);

        let original_size = u64::from_be_bytes(data[6..14].try_into().context("original size conversion")?);

        Ok((version, flags, original_size))
    }

    fn read_exact<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];

        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}
