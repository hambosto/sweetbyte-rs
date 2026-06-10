use anyhow::{Context, Result};

use crate::compression::CompressionLevel;
use crate::config::{CURRENT_VERSION, MAGIC_BYTES, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::Signer;
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::Section;
use crate::secret::Secret;

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

    #[inline]
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    #[inline]
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    #[inline]
    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(signer_key).context("failed to initialize signer")?;
        let mac = signer.compute_parts(&[salt, &params_bytes, &metadata_bytes]).context("failed to compute mac")?;
        let section = Section::new(CompressionLevel::Best, ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize section encoder")?;

        section.pack(salt, &params_bytes, &metadata_bytes, &mac).context("failed to pack header sections")
    }
}
