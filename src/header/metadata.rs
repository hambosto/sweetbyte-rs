use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::MAX_FILENAME_LEN;

#[nutype::nutype(
    validate(not_empty, len_char_max = MAX_FILENAME_LEN),
    derive(Debug, Clone, AsRef, Serialize, Deserialize)
)]
pub struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(Debug, Clone, AsRef, Serialize, Deserialize))]
pub struct FileSize(u64);

#[nutype::nutype(
    validate(predicate = |v| !v.is_empty()),
    derive(Debug, Clone, AsRef, Serialize, Deserialize)
)]
pub struct FileHash(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: Filename,
    size: FileSize,
    hash: FileHash,
}

impl Metadata {
    pub fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        Ok(Self { name: Filename::try_new(name.into())?, size: FileSize::try_new(size)?, hash: FileHash::try_new(hash)? })
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
