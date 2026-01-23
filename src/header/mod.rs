use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, HASH_SIZE,
    HEADER_DATA_SIZE, KDF_ARGON2, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS,
};
use crate::header::deserializer::{Deserializer, HeaderData};
use crate::header::metadata::FileMetadata;
use crate::header::section::{SectionEncoder, SectionType, Sections};
use crate::header::serializer::Serializer;

pub mod deserializer;
pub mod metadata;
pub mod section;
pub mod serializer;

pub struct Header {
    encoder: SectionEncoder,

    version: u16,

    algorithm: u8,

    compression: u8,

    encoding: u8,

    kdf: u8,

    kdf_memory: u32,

    kdf_time: u8,

    kdf_parallelism: u8,

    metadata: Option<FileMetadata>,

    sections: Option<Sections>,
}

impl Header {
    pub fn new(metadata: FileMetadata) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        Ok(Self {
            encoder,
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
            metadata: Some(metadata),
            sections: None,
        })
    }

    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let deserializer = Deserializer::new(&encoder);
        let parsed = deserializer.deserialize(reader)?;
        Self::from_parsed_data(parsed, encoder)
    }

    #[inline]
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.metadata.as_ref().map(|m| m.name()).unwrap_or("")
    }

    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.size())
    }

    #[inline]
    #[must_use]
    pub fn file_hash(&self) -> Option<&[u8; HASH_SIZE]> {
        self.metadata.as_ref().map(|m| m.hash())
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

    pub fn salt(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Salt, ARGON_SALT_LEN)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == CURRENT_VERSION, "unsupported version: {} (expected {})", self.version, CURRENT_VERSION);

        ensure!(self.algorithm == (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305), "invalid algorithm identifier: {:#04x}", self.algorithm);

        ensure!(self.compression == COMPRESSION_ZLIB, "invalid compression identifier: {:#04x}", self.compression);

        ensure!(self.encoding == ENCODING_REED_SOLOMON, "invalid encoding identifier: {:#04x}", self.encoding);

        ensure!(self.kdf == KDF_ARGON2, "invalid kdf identifier: {:#04x}", self.kdf);

        ensure!(self.file_size() != 0, "file size cannot be zero");

        Ok(())
    }

    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;

        let metadata = self.metadata.as_ref().context("metadata is required for serialization")?;

        let serializer = Serializer::new(&self.encoder);
        let params = serializer::SerializeParams {
            version: self.version,
            algorithm: self.algorithm,
            compression: self.compression,
            encoding: self.encoding,
            kdf: self.kdf,
            kdf_memory: self.kdf_memory,
            kdf_time: self.kdf_time,
            kdf_parallelism: self.kdf_parallelism,
            metadata,
            salt,
            key,
        };
        serializer.serialize(&params)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "key cannot be empty");

        let expected_mac = self.get_section(SectionType::Mac, MAC_SIZE)?;
        let magic = self.get_section(SectionType::Magic, MAGIC_SIZE)?;
        let salt = self.get_section(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = self.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

        let metadata = self.metadata.as_ref().context("metadata not available for verification")?;
        let metadata_bytes = metadata.serialize();

        Mac::new(key)?.verify(expected_mac, &[magic, salt, header_data, &metadata_bytes])
    }

    fn from_parsed_data(data: HeaderData, encoder: SectionEncoder) -> Result<Self> {
        let header = Self {
            encoder,
            version: data.version(),
            algorithm: data.algorithm(),
            compression: data.compression(),
            encoding: data.encoding(),
            kdf: data.kdf(),
            kdf_memory: data.kdf_memory(),
            kdf_time: data.kdf_time(),
            kdf_parallelism: data.kdf_parallelism(),
            metadata: Some(data.metadata().clone()),
            sections: Some(data.into_sections()),
        };

        header.validate()?;
        Ok(header)
    }

    fn get_section(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        self.sections.as_ref().context("header not deserialized yet")?.get_with_min_len(section_type, min_len)
    }
}
