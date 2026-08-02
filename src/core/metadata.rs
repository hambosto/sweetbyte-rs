use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{FileHash, FileSize, Filename};

#[derive(Serialize, Deserialize)]
pub(crate) struct Metadata {
    name: Filename,
    size: FileSize,
    hash: FileHash,
}

impl Metadata {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: &[u8]) -> Result<Self> {
        let name = Filename::try_new(name.into()).context("invalid filename")?;
        let size = FileSize::try_new(size).context("invalid file size")?;
        let hash = FileHash::try_new(hash.into()).context("invalid file hash")?;

        Ok(Self { name, size, hash })
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn size(&self) -> u64 {
        *self.size.as_ref()
    }

    pub(crate) fn hash(&self) -> &[u8] {
        self.hash.as_ref()
    }
}
