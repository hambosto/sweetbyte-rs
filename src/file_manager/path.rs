use crate::config::FILE_EXTENSION;
use crate::types::ProcessorMode;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Checks if a file is an encrypted file based on extension.
pub fn is_encrypted_file(path: &Path) -> bool {
    path.to_str()
        .map(|s| s.ends_with(FILE_EXTENSION))
        .unwrap_or(false)
}

/// Determines the output path based on input path and mode.
///
/// For encryption, appends the FILE_EXTENSION to the input path.
/// For decryption, removes the FILE_EXTENSION if present.
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

/// Validates a path for existence or non-existence.
///
/// # Arguments
///
/// * `path` - The path to validate
/// * `must_exist` - If true, validates that the path exists and is a non-empty file.
///   If false, validates that the path does NOT exist.
///
/// # Errors
///
/// Returns an error if validation fails, with context about what went wrong.
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
