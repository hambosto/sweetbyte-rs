use anyhow::{Context, Result};

use super::section::Section;
use crate::config::{COMPRESSION_LEVEL, CURRENT_VERSION, MAGIC_BYTES, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::{Metadata, Parameters, Secret};
use crate::crypto::Signer;

pub(crate) struct Serializer {
    params: Parameters,
    metadata: Metadata,
}

impl Serializer {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: &[u8]) -> Result<Self> {
        let params = Parameters::new(MAGIC_BYTES, CURRENT_VERSION).context("failed to initialize params")?;
        let metadata = Metadata::new(name, size, hash).context("failed to initialize metadata")?;

        Ok(Self { params, metadata })
    }

    pub(crate) fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(signer_key).context("failed to initialize signer")?;
        let mac = signer.compute_parts(&[salt, &params_bytes, &metadata_bytes]).context("failed to compute mac")?;
        let section = Section::new(COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize section encoder")?;

        section.pack(salt, &params_bytes, &metadata_bytes, &mac).context("failed to pack header sections")
    }
}
