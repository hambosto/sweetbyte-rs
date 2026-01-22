use anyhow::{Result, ensure};
use subtle::ConstantTimeEq;

use crate::config::CONTENT_HASH_SIZE;

pub struct ContentHash {
    hash: [u8; CONTENT_HASH_SIZE],
}

impl ContentHash {
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(data);
        let hash = *hasher.finalize().as_bytes();
        Self { hash }
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTENT_HASH_SIZE] {
        &self.hash
    }

    pub fn verify(&self, expected: &[u8; CONTENT_HASH_SIZE]) -> Result<()> {
        ensure!(bool::from(self.hash.ct_eq(expected)), "content hash verification failed: data integrity compromised");
        Ok(())
    }
}
