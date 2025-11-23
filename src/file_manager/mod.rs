pub mod config;
pub mod discovery;
pub mod io;
pub mod path;

use crate::types::ProcessorMode;
use anyhow::Result;
use std::fs::{self, File};

use config::FileConfig;
use discovery::Discovery;
use io::IoManager;
use path::PathManager;

/// FileManager handles file system operations including finding eligible files,
/// managing paths, and performing file I/O.
///
/// This struct now acts as a facade over specialized submodules.
pub struct FileManager {
    discovery: Discovery,
}

impl FileManager {
    /// Creates a new FileManager instance.
    pub fn new() -> Self {
        Self {
            discovery: Discovery::new(FileConfig::default()),
        }
    }

    /// Finds files eligible for the given processing mode.
    pub fn find_eligible_files(&self, mode: ProcessorMode) -> Result<Vec<String>> {
        self.discovery.find_eligible_files(mode)
    }

    /// Determines the output path based on input path and mode.
    pub fn get_output_path(&self, input_path: &str, mode: ProcessorMode) -> String {
        PathManager::get_output_path(input_path, mode)
    }

    /// Removes a file if it exists.
    pub fn remove(&self, path: &str) -> Result<()> {
        IoManager::remove(path)
    }

    /// Opens a file and returns the file handle and metadata.
    pub fn open_file(&self, path: &str) -> Result<(File, fs::Metadata)> {
        IoManager::open_file(path)
    }

    /// Validates a path for existence or non-existence.
    pub fn validate_path(&self, path: &str, must_exist: bool) -> Result<()> {
        PathManager::validate_path(path, must_exist)
    }
}

impl Default for FileManager {
    fn default() -> Self {
        Self::new()
    }
}
