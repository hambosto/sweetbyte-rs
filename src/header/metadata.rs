use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::MAX_FILENAME_LENGTH;

#[derive(Serialize, Deserialize, Clone)]
pub struct Metadata {
    name: String,
    size: u64,
    hash: Vec<u8>,
}

impl Metadata {
    pub fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let name = name.into();
        anyhow::ensure!(!name.is_empty(), "Filename cannot be empty");
        anyhow::ensure!(name.len() <= MAX_FILENAME_LENGTH, "Filename too long");
        anyhow::ensure!(size > 0, "File size must be positive");
        anyhow::ensure!(!hash.is_empty(), "Hash cannot be empty");

        Ok(Self { name, size, hash })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash
    }
}
