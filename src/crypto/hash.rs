use std::path::Path;

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;

pub(crate) fn hash(path: &Path) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new();
    hasher.update_mmap_rayon(path).context("failed to memory-map file for hashing")?;

    Ok(hasher.finalize().as_bytes().to_vec())
}

pub(crate) fn validate_hash(path: &Path, expected: &[u8]) -> Result<bool> {
    let actual = hash(path)?;

    Ok(bool::from(actual.as_slice().ct_eq(expected)))
}
