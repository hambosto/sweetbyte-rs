use wincode::{SchemaRead, SchemaWrite};

use crate::config::{HASH_SIZE, MAX_FILENAME_LENGTH};

#[derive(SchemaRead, SchemaWrite)]
pub struct Metadata {
    name: String,
    size: u64,
    hash: [u8; HASH_SIZE],
}

impl Metadata {
    pub fn new(filename: impl Into<String>, size: u64, content_hash: [u8; HASH_SIZE]) -> Self {
        let mut filename = filename.into();
        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        Self { name: filename, size, hash: content_hash }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}
