use crate::config::FILE_EXTENSION;
use crate::types::ProcessorMode;
use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

/// Handles path manipulation and validation.
pub struct PathManager;

impl PathManager {
    /// Checks if a file is an encrypted file based on extension.
    pub fn is_encrypted_file(path: &str) -> bool {
        path.ends_with(FILE_EXTENSION)
    }

    /// Determines the output path based on input path and mode.
    pub fn get_output_path(input_path: &str, mode: ProcessorMode) -> String {
        match mode {
            ProcessorMode::Encrypt => format!("{}{}", input_path, FILE_EXTENSION),
            ProcessorMode::Decrypt => {
                if input_path.ends_with(FILE_EXTENSION) {
                    input_path.trim_end_matches(FILE_EXTENSION).to_string()
                } else {
                    input_path.to_string()
                }
            }
        }
    }

    /// Validates a path for existence or non-existence.
    pub fn validate_path(path: &str, must_exist: bool) -> Result<()> {
        let file_path = Path::new(path);

        if must_exist {
            if !file_path.exists() {
                return Err(anyhow!("file not found: {}", path));
            }
            let metadata = fs::metadata(path)?;
            if metadata.is_dir() {
                return Err(anyhow!("path is directory: {}", path));
            }
            if metadata.len() == 0 {
                return Err(anyhow!("file is empty: {}", path));
            }
        } else {
            if file_path.exists() {
                return Err(anyhow!("output exists: {}", path));
            }
        }
        Ok(())
    }
}
