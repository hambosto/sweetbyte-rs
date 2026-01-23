use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, HASH_SIZE,
    HEADER_DATA_SIZE, KDF_ARGON2, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS,
};
use crate::header::deserializer::{Deserializer, HeaderData};
use crate::header::metadata::FileMetadata;
use crate::header::parameter::HeaderParameter;
use crate::header::section::{SectionDecoder, SectionEncoder, SectionType, Sections};
use crate::header::serializer::{SerializeParameter, Serializer};
pub mod deserializer;
pub mod metadata;
pub mod parameter;
pub mod section;
pub mod serializer;

pub struct Header {
    encoder: SectionEncoder,
    parameter: HeaderParameter,
    metadata: FileMetadata,
    sections: Option<Sections>,
}

impl Header {
    pub fn new(metadata: FileMetadata) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let parameter = HeaderParameter {
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
        };
        Self::new_with_parameter(encoder, parameter, metadata)
    }

    pub fn new_with_parameter(encoder: SectionEncoder, params: HeaderParameter, metadata: FileMetadata) -> Result<Self> {
        Self::validate(&params)?;
        ensure!(metadata.size() != 0, "file size cannot be zero");
        Ok(Self { encoder, parameter: params, metadata, sections: None })
    }

    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let decoder = SectionDecoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let deserializer = Deserializer::new(&decoder);
        let parsed = deserializer.deserialize(reader)?;
        Self::from_parsed_data(parsed, encoder)
    }

    #[inline]
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    #[inline]
    #[must_use]
    pub fn file_hash(&self) -> &[u8; HASH_SIZE] {
        self.metadata.hash()
    }

    #[inline]
    #[must_use]
    pub const fn kdf_memory(&self) -> u32 {
        self.parameter.kdf_memory
    }

    #[inline]
    #[must_use]
    pub const fn kdf_time(&self) -> u8 {
        self.parameter.kdf_time
    }

    #[inline]
    #[must_use]
    pub const fn kdf_parallelism(&self) -> u8 {
        self.parameter.kdf_parallelism
    }

    pub fn salt(&self) -> Result<&[u8]> {
        self.sections.as_ref().context("header not deserialized yet")?.get_with_min_len(SectionType::Salt, ARGON_SALT_LEN)
    }

    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let serializer = Serializer::new(&self.encoder);
        let serialize_params = SerializeParameter { params: self.parameter, metadata: &self.metadata, salt, key };
        serializer.serialize(&serialize_params)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "key cannot be empty");
        let sections = self.sections.as_ref().context("header not deserialized yet")?;
        let expected_mac = sections.get_with_min_len(SectionType::Mac, MAC_SIZE)?;
        let magic = sections.get_with_min_len(SectionType::Magic, MAGIC_SIZE)?;
        let salt = sections.get_with_min_len(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = sections.get_with_min_len(SectionType::HeaderData, HEADER_DATA_SIZE)?;
        let metadata_bytes = self.metadata.serialize();
        Mac::new(key)?.verify(expected_mac, &[magic, salt, header_data, &metadata_bytes])
    }

    fn from_parsed_data(data: HeaderData, encoder: SectionEncoder) -> Result<Self> {
        let params = *data.parameters();
        Self::validate(&params)?;
        ensure!(data.metadata().size() != 0, "file size cannot be zero");
        Ok(Self { encoder, parameter: params, metadata: data.metadata().clone(), sections: Some(data.into_sections()) })
    }

    fn validate(params: &HeaderParameter) -> Result<()> {
        ensure!(params.version == CURRENT_VERSION, "unsupported version: {} (expected {})", params.version, CURRENT_VERSION);
        ensure!(params.algorithm == (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305), "invalid algorithm identifier: {:#04x}", params.algorithm);
        ensure!(params.compression == COMPRESSION_ZLIB, "invalid compression identifier: {:#04x}", params.compression);
        ensure!(params.encoding == ENCODING_REED_SOLOMON, "invalid encoding identifier: {:#04x}", params.encoding);
        ensure!(params.kdf == KDF_ARGON2, "invalid kdf identifier: {:#04x}", params.kdf);
        Ok(())
    }
}
