use crate::types::ProcessorMode;
use anyhow::Result;
use walkdir::WalkDir;

use super::config::FileConfig;
use super::path::PathManager;

/// Handles file discovery.
pub struct Discovery {
    config: FileConfig,
}

impl Discovery {
    /// Creates a new Discovery instance.
    pub fn new(config: FileConfig) -> Self {
        Self { config }
    }

    /// Finds files eligible for the given processing mode.
    pub fn find_eligible_files(&self, mode: ProcessorMode) -> Result<Vec<String>> {
        let mut files = Vec::new();

        for entry in WalkDir::new(".")
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !self.config.is_excluded_dir(e.path()))
        {
            let entry = entry?;
            if entry.file_type().is_file() {
                let path = entry.path();
                if self.is_eligible(path, mode) {
                    if let Some(path_str) = path.to_str() {
                        files.push(path_str.to_string());
                    }
                }
            }
        }
        Ok(files)
    }

    fn is_eligible(&self, path: &std::path::Path, mode: ProcessorMode) -> bool {
        let path_str = match path.to_str() {
            Some(s) => s,
            None => return false,
        };

        if self.config.is_excluded_ext(path_str) {
            return false;
        }

        let is_encrypted = PathManager::is_encrypted_file(path_str);
        match mode {
            ProcessorMode::Encrypt => !is_encrypted,
            ProcessorMode::Decrypt => is_encrypted,
        }
    }
}
