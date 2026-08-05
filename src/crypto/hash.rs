use std::path::Path;

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;

pub(crate) fn validate_hash(path: &Path, expected: &[u8]) -> Result<bool> {
    let mut hasher = Hasher::new();
    hasher.update_mmap_rayon(path).context("failed to hash file")?;

    let actual = *hasher.finalize().as_bytes();

    Ok(bool::from(actual.ct_eq(expected)))
}
