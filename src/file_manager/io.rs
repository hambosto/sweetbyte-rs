use anyhow::{anyhow, Result};
use std::fs::{self, File};
use std::path::Path;

/// Handles file system I/O operations.
pub struct IoManager;

impl IoManager {
    /// Removes a file if it exists.
    pub fn remove(path: &str) -> Result<()> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            return Ok(());
        }
        fs::remove_file(file_path).map_err(|e| anyhow!("failed to delete file '{}': {}", path, e))
    }

    /// Opens a file and returns the file handle and metadata.
    pub fn open_file(path: &str) -> Result<(File, fs::Metadata)> {
        let file = File::open(path).map_err(|e| anyhow!("open failed: {}", e))?;
        let info = file.metadata().map_err(|e| anyhow!("stat failed: {}", e))?;
        Ok((file, info))
    }
}
