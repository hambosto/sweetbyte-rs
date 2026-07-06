use anyhow::{Context, Result};

use super::serializer::Serializer;
use crate::secret::Secret;

pub(crate) struct WriteHeader {
    serializer: Serializer,
}

impl WriteHeader {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let serializer = Serializer::new(name, size, hash).context("failed to create header serializer")?;

        Ok(Self { serializer })
    }

    pub(crate) fn name(&self) -> &str {
        self.serializer.file_name()
    }

    pub(crate) fn size(&self) -> u64 {
        self.serializer.file_size()
    }

    pub(crate) fn hash(&self) -> &[u8] {
        self.serializer.file_hash()
    }

    pub(crate) fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        self.serializer.serialize(salt, signer_key)
    }
}
