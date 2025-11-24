use anyhow::{Context, Result};
use std::fs::{self, File};
use std::path::Path;

/// Removes a file if it exists.
///
/// This is a safe operation that succeeds even if the file doesn't exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be deleted.
pub fn remove(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    fs::remove_file(path).with_context(|| format!("failed to delete file: {}", path.display()))
}

/// Opens a file and returns the file handle and metadata.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or metadata cannot be read.
pub fn open_file(path: &Path) -> Result<(File, fs::Metadata)> {
    let file =
        File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to read file metadata: {}", path.display()))?;

    Ok((file, metadata))
}
