use anyhow::{Context, Result};

use super::section::Section;
use crate::config::{COMPRESSION_LEVEL, CURRENT_VERSION, MAGIC_BYTES, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::{Metadata, Parameters, Secret};
use crate::crypto::Signer;

pub(crate) struct Serializer {
    parameters: Parameters,
    metadata: Metadata,
}

impl Serializer {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: &[u8]) -> Result<Self> {
        let parameters = Parameters::new(MAGIC_BYTES, CURRENT_VERSION).context("failed to construct parameters")?;
        let metadata = Metadata::new(name, size, hash).context("failed to construct metadata")?;

        Ok(Self { parameters, metadata })
    }

    pub(crate) fn to_bytes(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        let encoded_parameters = postcard::to_allocvec(&self.parameters).context("failed to encode header parameters")?;
        let encoded_metadata = postcard::to_allocvec(&self.metadata).context("failed to encode header metadata")?;
        let signer = Signer::new(signer_key).context("failed to init auth signer")?;
        let mac = signer.compute_parts(&[salt, &encoded_parameters, &encoded_metadata]).context("failed to sign header")?;
        let section = Section::new(COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to init header encoder")?;

        section.pack(salt, &encoded_parameters, &encoded_metadata, &mac).context("failed to construct header")
    }
}
