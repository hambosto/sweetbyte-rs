//! File discovery for batch encryption/decryption operations.
//!
//! This module provides functionality to find files eligible for processing
//! based on the operation mode (encrypt/decrypt) and configured exclusion rules.

use crate::file::validation;
use crate::types::ProcessorMode;
use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

/// Finds files eligible for the given processing mode.
///
/// This function walks through the current directory recursively, excluding
/// configured directories and file extensions, and returns paths that are
/// eligible based on the processing mode:
/// - For encryption: returns non-encrypted files
/// - For decryption: returns encrypted files
///
/// # Arguments
///
/// * `mode` - The processing mode (Encrypt or Decrypt)
///
/// # Returns
///
/// Returns a vector of `PathBuf` containing all eligible file paths.
///
/// # Errors
///
/// Returns an error if directory traversal fails catastrophically.
/// Individual file access errors are silently skipped.
///
/// # Examples
///
/// ```no_run
/// use sweetbyte::file::discovery::find_eligible_files;
/// use sweetbyte::types::ProcessorMode;
///
/// // Find all files that can be encrypted
/// let files = find_eligible_files(ProcessorMode::Encrypt)?;
/// println!("Found {} files to encrypt", files.len());
///
/// // Find all encrypted files that can be decrypted
/// let encrypted_files = find_eligible_files(ProcessorMode::Decrypt)?;
/// println!("Found {} encrypted files", encrypted_files.len());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn find_eligible_files(mode: ProcessorMode) -> Result<Vec<PathBuf>> {
    let files = WalkDir::new(".")
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !validation::is_excluded_dir(e.path()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if !entry.file_type().is_file() {
                return None;
            }

            let path = entry.path();
            if is_eligible(path, mode) {
                Some(path.to_path_buf())
            } else {
                None
            }
        })
        .collect();

    Ok(files)
}

/// Checks if a file is eligible for the given processing mode.
///
/// # Arguments
///
/// * `path` - The file path to check
/// * `mode` - The processing mode
///
/// # Returns
///
/// Returns `true` if the file is eligible for processing, `false` otherwise.
fn is_eligible(path: &std::path::Path, mode: ProcessorMode) -> bool {
    // Skip files with excluded extensions
    if validation::is_excluded_ext(path) {
        return false;
    }

    // Check if file is encrypted
    let is_encrypted = validation::is_encrypted_file(path);

    // For encryption: only non-encrypted files are eligible
    // For decryption: only encrypted files are eligible
    match mode {
        ProcessorMode::Encrypt => !is_encrypted,
        ProcessorMode::Decrypt => is_encrypted,
    }
}
