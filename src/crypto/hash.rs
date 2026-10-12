use std::path::PathBuf;

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;

pub(crate) struct Hash {
    path: PathBuf,
}

impl Hash {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn compute(&self) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        hasher.update_mmap_rayon(&self.path).context("failed to hash file")?;

        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn verify(&self, expected: &[u8]) -> Result<bool> {
        let actual = self.compute().context("failed to verify file hash")?;

        Ok(bool::from(actual.ct_eq(expected)))
    }
}
