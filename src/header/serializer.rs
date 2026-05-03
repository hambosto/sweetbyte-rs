use anyhow::{Context, Result};

use crate::config::{CURRENT_VERSION, DATA_SHARDS, MAGIC_BYTES, PARITY_SHARDS};
use crate::core::Signer;
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::SectionShield;
use crate::secret::SecretBytes;

pub struct Serializer {
    params: Parameters,
    metadata: Metadata,
}

impl Serializer {
    pub fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let params = Parameters::new(MAGIC_BYTES, CURRENT_VERSION).context("failed to initialize params")?;
        let metadata = Metadata::new(name, size, hash).context("failed to initialize metadata")?;

        Ok(Self { params, metadata })
    }

    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn serialize(&self, salt: &[u8], key: &SecretBytes) -> Result<Vec<u8>> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(key).context("failed to initialize signer")?;
        let mac = signer.compute_parts(&[salt, &params_bytes, &metadata_bytes]).context("failed to compute mac")?;
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS).context("failed to initialize shield")?;

        shield.pack(salt, &params_bytes, &metadata_bytes, &mac).context("failed to pack header sections")
    }
}
