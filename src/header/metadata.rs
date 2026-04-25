use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::MAX_FILENAME_LEN;

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    size: u64,
    hash: Vec<u8>,
}

impl Metadata {
    pub fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let name = name.into();
        anyhow::ensure!(!name.is_empty(), "empty filename");
        anyhow::ensure!(name.len() <= MAX_FILENAME_LEN, "filename too long");
        anyhow::ensure!(size > 0, "invalid size");
        anyhow::ensure!(!hash.is_empty(), "empty hash");

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
