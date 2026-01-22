use std::io::Read;

use anyhow::{Context, Result, anyhow, ensure};

use crate::config::{CONTENT_HASH_SIZE, HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::metadata::FileMetadata;
use crate::header::section::{EncodedSection, SectionEncoder, SectionType, Sections, SectionsBuilder};

struct HeaderParams {
    version: u16,
    algorithm: u8,
    compression: u8,
    encoding: u8,
    kdf: u8,
    kdf_memory: u32,
    kdf_time: u8,
    kdf_parallelism: u8,
}

pub struct HeaderData {
    version: u16,

    algorithm: u8,

    compression: u8,

    encoding: u8,

    kdf: u8,

    kdf_memory: u32,

    kdf_time: u8,

    kdf_parallelism: u8,

    metadata: FileMetadata,

    content_hash: [u8; CONTENT_HASH_SIZE],

    sections: Sections,
}

impl HeaderData {
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    #[inline]
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    #[inline]
    #[must_use]
    pub const fn compression(&self) -> u8 {
        self.compression
    }

    #[inline]
    #[must_use]
    pub const fn encoding(&self) -> u8 {
        self.encoding
    }

    #[inline]
    #[must_use]
    pub const fn kdf(&self) -> u8 {
        self.kdf
    }

    #[inline]
    #[must_use]
    pub const fn kdf_memory(&self) -> u32 {
        self.kdf_memory
    }

    #[inline]
    #[must_use]
    pub const fn kdf_time(&self) -> u8 {
        self.kdf_time
    }

    #[inline]
    #[must_use]
    pub const fn kdf_parallelism(&self) -> u8 {
        self.kdf_parallelism
    }

    #[inline]
    #[must_use]
    pub const fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    #[inline]
    #[must_use]
    pub const fn content_hash(&self) -> &[u8; CONTENT_HASH_SIZE] {
        &self.content_hash
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
    pub const fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<HeaderData> {
        let length_sizes = Self::read_lengths_header(&mut reader)?;

        let section_lengths = self.read_and_decode_lengths(&mut reader, &length_sizes)?;

        let sections = self.read_and_decode_sections(&mut reader, &section_lengths)?;

        let magic = sections.get_with_min_len(SectionType::Magic, MAGIC_SIZE)?;
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes: expected {:?}, got {:?}", MAGIC_BYTES.to_be_bytes(), magic);

        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow::anyhow!("HeaderData section not found"))?;
        let params = Self::parse_header_data(header_data)?;
        let (version, algorithm, compression, encoding, kdf, kdf_memory, kdf_time, kdf_parallelism) =
            (params.version, params.algorithm, params.compression, params.encoding, params.kdf, params.kdf_memory, params.kdf_time, params.kdf_parallelism);

        let metadata_bytes = sections.get(SectionType::Metadata).ok_or_else(|| anyhow::anyhow!("Metadata section not found"))?;
        let metadata = FileMetadata::deserialize(metadata_bytes)?;

        let content_hash_bytes = sections.get_with_min_len(SectionType::ContentHash, CONTENT_HASH_SIZE)?;
        let content_hash: [u8; CONTENT_HASH_SIZE] = content_hash_bytes.try_into().context("content hash conversion")?;

        Ok(HeaderData { version, algorithm, compression, encoding, kdf, kdf_memory, kdf_time, kdf_parallelism, metadata, content_hash, sections })
    }

    fn read_lengths_header<R: Read>(reader: &mut R) -> Result<[u32; 6]> {
        let header = Self::read_exact::<24, R>(reader).context("failed to read lengths header")?;

        Ok([
            u32::from_be_bytes(header[0..4].try_into().context("magic length conversion")?),
            u32::from_be_bytes(header[4..8].try_into().context("salt length conversion")?),
            u32::from_be_bytes(header[8..12].try_into().context("header data length conversion")?),
            u32::from_be_bytes(header[12..16].try_into().context("metadata length conversion")?),
            u32::from_be_bytes(header[16..20].try_into().context("content hash length conversion")?),
            u32::from_be_bytes(header[20..24].try_into().context("mac length conversion")?),
        ])
    }

    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; 6]) -> Result<[u32; 6]> {
        let mut decoded_lengths = Vec::with_capacity(6);

        for (&section_type, &size) in SectionType::ALL.iter().zip(length_sizes) {
            let mut encoded = vec![0u8; size as usize];
            reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded length for {section_type}"))?;

            let section = EncodedSection::new(encoded);
            let decoded = self.encoder.decode_length(&section)?;
            decoded_lengths.push(decoded);
        }

        decoded_lengths.try_into().map_err(|_| anyhow!("section count mismatch"))
    }

    fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 6]) -> Result<Sections> {
        let magic = self.read_section(reader, SectionType::Magic, section_lengths[0])?;
        let mut builder = SectionsBuilder::with_magic(magic);

        for (&section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let decoded = self.read_section(reader, section_type, length)?;
            builder.set(section_type, decoded);
        }

        builder.build()
    }

    fn read_section<R: Read>(&self, reader: &mut R, section_type: SectionType, length: u32) -> Result<Vec<u8>> {
        let mut encoded = vec![0u8; length as usize];
        reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded {section_type}"))?;

        let section = EncodedSection::new(encoded);
        self.encoder.decode_section(&section)
    }

    fn parse_header_data(data: &[u8]) -> Result<HeaderParams> {
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);
        let algorithm = data[2];
        let compression = data[3];
        let encoding = data[4];
        let kdf = data[5];
        let kdf_memory = u32::from_be_bytes(data[6..10].try_into().context("kdf memory conversion")?);
        let kdf_time = data[10];
        let kdf_parallelism = data[11];

        Ok(HeaderParams { version, algorithm, compression, encoding, kdf, kdf_memory, kdf_time, kdf_parallelism })
    }

    fn read_exact<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}
