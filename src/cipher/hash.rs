use anyhow::{Result, ensure};
use subtle::ConstantTimeEq;

use crate::config::HASH_SIZE;

pub struct Hash {
    hash: [u8; HASH_SIZE],
}

impl Hash {
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(data);
        let hash = *hasher.finalize().as_bytes();
        Self { hash }
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }

    pub fn verify(&self, expected: &[u8; HASH_SIZE]) -> Result<()> {
        ensure!(bool::from(self.hash.ct_eq(expected)), "content hash verification failed: data integrity compromised");
        Ok(())
    }
}
