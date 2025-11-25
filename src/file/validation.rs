//! Path validation and filtering utilities.
//!
//! This module provides functions for validating paths, determining output paths,
//! and filtering files based on encryption status or exclusion rules.

use crate::config::{EXCLUDED_DIRS, EXCLUDED_EXTS, FILE_EXTENSION};
use crate::types::ProcessorMode;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Validates a path for existence or non-existence.
///
/// This function checks path validity based on the `must_exist` parameter.
/// When `must_exist` is true, it validates that the path exists, is a file
/// (not a directory), and is non-empty. When false, it validates that the
/// path does NOT exist.
///
/// # Arguments
///
/// * `path` - The path to validate
/// * `must_exist` - If true, validates existence; if false, validates non-existence
///
/// # Errors
///
/// Returns an error in the following cases:
/// - If `must_exist` is true and the path doesn't exist
/// - If `must_exist` is true and the path is a directory
/// - If `must_exist` is true and the file is empty (0 bytes)
/// - If `must_exist` is false and the path already exists
pub fn validate_path(path: &Path, must_exist: bool) -> Result<()> {
    if must_exist {
        if !path.exists() {
            anyhow::bail!("file not found: {}", path.display());
        }

        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to read metadata for: {}", path.display()))?;

        if metadata.is_dir() {
            anyhow::bail!("path is a directory, not a file: {}", path.display());
        }

        if metadata.len() == 0 {
            anyhow::bail!("file is empty: {}", path.display());
        }
    } else if path.exists() {
        anyhow::bail!("output file already exists: {}", path.display());
    }

    Ok(())
}

/// Determines the output path based on input path and processing mode.
///
/// For encryption mode, this appends the encrypted file extension to the input path.
/// For decryption mode, this removes the encrypted file extension if present.
///
/// # Arguments
///
/// * `input_path` - The input file path
/// * `mode` - The processing mode (Encrypt or Decrypt)
///
/// # Returns
///
/// Returns a `PathBuf` representing the appropriate output path for the given mode.
pub fn get_output_path(input_path: &Path, mode: ProcessorMode) -> PathBuf {
    match mode {
        ProcessorMode::Encrypt => {
            let mut output = input_path.as_os_str().to_os_string();
            output.push(FILE_EXTENSION);
            PathBuf::from(output)
        }
        ProcessorMode::Decrypt => input_path
            .to_str()
            .and_then(|s| s.strip_suffix(FILE_EXTENSION))
            .map(PathBuf::from)
            .unwrap_or_else(|| input_path.to_path_buf()),
    }
}

/// Determines the output path and returns both actual and cleaned display paths.
///
/// This is a convenience function that combines `get_output_path` with path cleaning
/// for display purposes.
///
/// # Arguments
///
/// * `input_path` - The input file path
/// * `mode` - The processing mode (Encrypt or Decrypt)
///
/// # Returns
///
/// Returns a tuple `(PathBuf, String)` where:
/// - First element is the actual output path for processing
/// - Second element is the cleaned path for display to users
pub fn get_output_path_with_display(input_path: &Path, mode: ProcessorMode) -> (PathBuf, String) {
    let output_path = get_output_path(input_path, mode);
    let display_path = clean_path(&output_path);
    (output_path, display_path)
}

/// Returns a cleaned path for display purposes.
///
/// This is a convenience wrapper around the internal `clean_path` function,
/// provided for cases where only path cleaning is needed (e.g., for input paths).
///
/// # Arguments
///
/// * `path` - The path to clean
///
/// # Returns
///
/// Returns a cleaned path as a `String`.
pub fn get_clean_path(path: &Path) -> String {
    clean_path(path)
}

/// Checks if a file is an encrypted file based on its extension.
///
/// # Arguments
///
/// * `path` - The path to check
///
/// # Returns
///
/// Returns `true` if the path ends with the encrypted file extension, `false` otherwise.
pub fn is_encrypted_file(path: &Path) -> bool {
    path.to_str()
        .map(|s| s.ends_with(FILE_EXTENSION))
        .unwrap_or(false)
}

/// Checks if a directory should be excluded from processing.
///
/// This walks through all path components and checks if any component
/// matches an excluded directory name from the global configuration.
///
/// # Arguments
///
/// * `path` - The path to check
///
/// # Returns
///
/// Returns `true` if the path contains any excluded directory component,
/// `false` otherwise.
pub fn is_excluded_dir(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|name| {
                EXCLUDED_DIRS
                    .iter()
                    .any(|dir| dir.trim_end_matches('/') == name)
            })
            .unwrap_or(false)
    })
}

/// Checks if a file should be excluded based on its extension or filename.
///
/// This checks against both file extensions (e.g., ".rs") and full filename
/// patterns (e.g., "go.mod") from the global configuration.
///
/// # Arguments
///
/// * `path` - The path to check
///
/// # Returns
///
/// Returns `true` if the file matches any excluded extension or pattern,
/// `false` otherwise.
pub fn is_excluded_ext(path: &Path) -> bool {
    path.to_str()
        .map(|path_str| EXCLUDED_EXTS.iter().any(|ext| path_str.ends_with(ext)))
        .unwrap_or(false)
}

/// Cleans a path for display by stripping the "./" prefix.
///
/// This normalizes path display for user-facing output, removing the
/// current directory prefix that is commonly added during file traversal.
///
/// # Arguments
///
/// * `path` - The path to clean
///
/// # Returns
///
/// Returns a cleaned path as a `String`.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// let path = Path::new("./file.txt");
/// let clean = clean_path(path);
/// assert_eq!(clean, "file.txt");
/// ```
pub fn clean_path(path: &Path) -> String {
    path.strip_prefix(".")
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}
