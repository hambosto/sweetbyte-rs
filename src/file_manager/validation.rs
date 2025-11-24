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
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::validation::validate_path;
///
/// // Validate that input file exists and is non-empty
/// validate_path(Path::new("input.txt"), true)?;
///
/// // Validate that output file doesn't exist yet
/// validate_path(Path::new("output.txt.enc"), false)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
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
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::validation::get_output_path;
/// use sweetbyte::types::ProcessorMode;
///
/// let input = Path::new("document.pdf");
/// let output = get_output_path(input, ProcessorMode::Encrypt);
/// assert_eq!(output, Path::new("document.pdf.enc"));
///
/// let encrypted = Path::new("document.pdf.enc");
/// let output = get_output_path(encrypted, ProcessorMode::Decrypt);
/// assert_eq!(output, Path::new("document.pdf"));
/// ```
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

/// Checks if a file is an encrypted file based on its extension.
///
/// # Arguments
///
/// * `path` - The path to check
///
/// # Returns
///
/// Returns `true` if the path ends with the encrypted file extension, `false` otherwise.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::validation::is_encrypted_file;
///
/// assert!(is_encrypted_file(Path::new("document.pdf.enc")));
/// assert!(!is_encrypted_file(Path::new("document.pdf")));
/// ```
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
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::validation::is_excluded_dir;
///
/// assert!(is_excluded_dir(Path::new(".git/objects")));
/// assert!(is_excluded_dir(Path::new("target/debug/deps")));
/// assert!(!is_excluded_dir(Path::new("src/main.rs")));
/// ```
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
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use sweetbyte::file_manager::validation::is_excluded_ext;
///
/// assert!(is_excluded_ext(Path::new("main.rs")));
/// assert!(is_excluded_ext(Path::new("go.mod")));
/// assert!(!is_excluded_ext(Path::new("document.pdf")));
/// ```
pub fn is_excluded_ext(path: &Path) -> bool {
    path.to_str()
        .map(|path_str| EXCLUDED_EXTS.iter().any(|ext| path_str.ends_with(ext)))
        .unwrap_or(false)
}
