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
        if name.is_empty() {
            anyhow::bail!("filename must not be empty");
        }
        if name.len() > MAX_FILENAME_LEN {
            anyhow::bail!("filename too long: max {MAX_FILENAME_LEN} characters");
        }
        if size == 0 {
            anyhow::bail!("file size must be greater than zero");
        }
        if hash.is_empty() {
            anyhow::bail!("hash must not be empty");
        }

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
