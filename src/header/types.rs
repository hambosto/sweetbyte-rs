use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{CURRENT_VERSION, MAGIC_BYTES, MAX_FILENAME_LENGTH};

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

#[derive(Serialize, Deserialize, Clone)]
pub struct Parameters {
    magic: u32,
    version: u16,
}

impl Parameters {
    pub fn new(magic: u32, version: u16) -> Self {
        Self { magic, version }
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.magic == MAGIC_BYTES, "Invalid magic: {:08X}", self.magic);
        anyhow::ensure!(self.version == CURRENT_VERSION, "Invalid version: {}", self.version);
        Ok(())
    }
}
