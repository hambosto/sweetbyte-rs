use crate::types::ProcessorMode;
use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

use super::config::FileConfig;
use super::path;

/// Handles file discovery for encryption/decryption operations.
pub struct Discovery {
    config: FileConfig,
}

impl Discovery {
    /// Creates a new Discovery instance.
    pub const fn new(config: FileConfig) -> Self {
        Self { config }
    }

    /// Finds files eligible for the given processing mode.
    ///
    /// This walks through the current directory recursively, excluding
    /// configured directories and extensions, and returns paths that are
    /// eligible based on the processing mode.
    pub fn find_eligible_files(&self, mode: ProcessorMode) -> Result<Vec<PathBuf>> {
        let files = WalkDir::new(".")
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !self.config.is_excluded_dir(e.path()))
            .filter_map(|entry| {
                let entry = entry.ok()?;
                if !entry.file_type().is_file() {
                    return None;
                }

                let path = entry.path();
                if self.is_eligible(path, mode) {
                    Some(path.to_path_buf())
                } else {
                    None
                }
            })
            .collect();

        Ok(files)
    }

    /// Checks if a file is eligible for the given processing mode.
    fn is_eligible(&self, path: &std::path::Path, mode: ProcessorMode) -> bool {
        if self.config.is_excluded_ext(path) {
            return false;
        }

        let is_encrypted = path::is_encrypted_file(path);
        match mode {
            ProcessorMode::Encrypt => !is_encrypted,
            ProcessorMode::Decrypt => is_encrypted,
        }
    }
}
