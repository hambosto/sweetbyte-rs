use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, KDF_ARGON2,
    MAGIC_BYTES, MAX_FILENAME_LENGTH, PARITY_SHARDS,
};
use crate::header::metadata::Metadata;
use crate::header::parameter::Parameters;
use crate::header::section::{DecodedSections, SectionShield};

pub mod metadata;
pub mod parameter;
pub mod section;

pub struct Header {
    shield: SectionShield,
    parameters: Parameters,
    metadata: Metadata,
    sections: Option<DecodedSections>,
}

impl Header {
    pub fn new(metadata: Metadata) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let parameters = Parameters {
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
        };

        Self::new_with_parameter(shield, parameters, metadata)
    }

    pub fn new_with_parameter(shield: SectionShield, parameters: Parameters, metadata: Metadata) -> Result<Self> {
        parameters.validate()?;

        if metadata.size() == 0 {
            anyhow::bail!("zero-size file");
        }

        Ok(Self { shield, parameters, metadata, sections: None })
    }

    pub async fn deserialize<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let sections = shield.unpack(&mut reader).await?;
        let params: Parameters = wincode::deserialize(&sections.header_data)?;
        let metadata: Metadata = wincode::deserialize(&sections.metadata)?;
        params.validate()?;

        if metadata.size() == 0 {
            anyhow::bail!("zero-size file");
        }

        if metadata.name().len() > MAX_FILENAME_LENGTH {
            anyhow::bail!("filename exceeds max length")
        }

        Ok(Self { shield, parameters: params, metadata, sections: Some(sections) })
    }

    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub fn file_hash(&self) -> String {
        self.metadata.hash().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub const fn kdf_memory(&self) -> u32 {
        self.parameters.kdf_memory
    }

    pub const fn kdf_time(&self) -> u8 {
        self.parameters.kdf_time
    }

    pub const fn kdf_parallelism(&self) -> u8 {
        self.parameters.kdf_parallelism
    }

    pub fn salt(&self) -> Result<&[u8]> {
        Ok(&self.sections.as_ref().context("header not deserialized")?.salt)
    }

    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if salt.len() != ARGON_SALT_LEN {
            anyhow::bail!("invalid salt length");
        }

        if key.is_empty() {
            anyhow::bail!("empty key");
        }

        let magic = MAGIC_BYTES.to_be_bytes();
        let header_data = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;
        let mac = Mac::new(key)?.compute_parts(&[&magic, salt, &header_data, &metadata_bytes])?;

        self.shield.pack(&magic, salt, &header_data, &metadata_bytes, &mac)
    }

    pub fn verify(&self, key: &[u8]) -> Result<()> {
        if key.is_empty() {
            anyhow::bail!("empty key");
        }

        let sections = self.sections.as_ref().context("header not loaded")?;
        let expected_mac = &sections.mac;
        let magic = &sections.magic;
        let salt = &sections.salt;
        let header_data = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;

        Mac::new(key)?.verify_parts(expected_mac, &[magic, salt, &header_data, &metadata_bytes])
    }
}
