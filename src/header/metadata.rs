use anyhow::Result;
use wincode::{SchemaRead, SchemaWrite};

use crate::config::MAX_FILENAME_LENGTH;

#[derive(SchemaRead, SchemaWrite)]
pub struct Metadata {
    name: String,
    size: u64,
    hash: Vec<u8>,
}

impl Metadata {
    pub fn new(filename: impl Into<String>, size: u64, content_hash: Vec<u8>) -> Result<Self> {
        let filename = filename.into();
        if filename.len() > MAX_FILENAME_LENGTH {
            anyhow::bail!("filename exceeds maximum length of {MAX_FILENAME_LENGTH} characters");
        }

        Ok(Self { name: filename, size, hash: content_hash })
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
