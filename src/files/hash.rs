use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;

use super::handle::Files;

pub(crate) fn hash(file: &Files) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new();
    hasher.update_mmap_rayon(file.path()).context("failed to memory-map file for hashing")?;

    Ok(hasher.finalize().as_bytes().to_vec())
}

pub(crate) fn validate_hash(file: &Files, expected: &[u8]) -> Result<bool> {
    let actual = hash(file)?;

    Ok(bool::from(actual.as_slice().ct_eq(expected)))
}
