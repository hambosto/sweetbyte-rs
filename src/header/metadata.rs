use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::validation::{FileHash, FileSize, Filename};

#[derive(Serialize, Deserialize)]
pub(super) struct Metadata {
    name: Filename,
    size: FileSize,
    hash: FileHash,
}

impl Metadata {
    pub(super) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let name = Filename::try_new(name.into()).context("invalid filename")?;
        let size = FileSize::try_new(size).context("invalid file size")?;
        let hash = FileHash::try_new(hash).context("invalid file hash")?;

        Ok(Self { name, size, hash })
    }

    pub(super) fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(super) fn size(&self) -> u64 {
        *self.size.as_ref()
    }

    pub(super) fn hash(&self) -> &[u8] {
        self.hash.as_ref()
    }
}
