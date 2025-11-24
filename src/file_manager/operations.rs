//! Core file I/O operations for SweetByte.
//!
//! This module provides fundamental file operations needed for encryption
//! and decryption workflows.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::path::Path;

/// Opens a file and returns the file handle and metadata.
///
/// # Arguments
///
/// * `path` - The path to the file to open
///
/// # Returns
///
/// Returns a tuple of `(File, Metadata)` containing the file handle and its metadata.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or metadata cannot be read.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::operations::open_file;
///
/// let (file, metadata) = open_file(Path::new("example.txt"))?;
/// println!("File size: {} bytes", metadata.len());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn open_file(path: &Path) -> Result<(File, fs::Metadata)> {
    let file =
        File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to read file metadata: {}", path.display()))?;

    Ok((file, metadata))
}

/// Removes a file if it exists.
///
/// This is a safe operation that succeeds even if the file doesn't exist.
/// It's useful for cleanup operations where you want to ensure a file is gone
/// without failing if it was already removed.
///
/// # Arguments
///
/// * `path` - The path to the file to remove
///
/// # Errors
///
/// Returns an error if the file exists but cannot be deleted due to permissions
/// or other I/O errors.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::operations::remove_file;
///
/// // Safe to call even if file doesn't exist
/// remove_file(Path::new("temp.txt"))?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn remove_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    fs::remove_file(path).with_context(|| format!("failed to delete file: {}", path.display()))
}
