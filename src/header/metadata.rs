use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::validation::{FileHash, FileSize, Filename};

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: Filename,
    size: FileSize,
    hash: FileHash,
}

impl Metadata {
    pub fn new(name: String, size: u64, hash: Vec<u8>) -> Result<Self> {
        Ok(Self { name: Filename::try_new(name)?, size: FileSize::try_new(size)?, hash: FileHash::try_new(hash)? })
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn size(&self) -> u64 {
        *self.size.as_ref()
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.as_ref()
    }
}
