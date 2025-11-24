pub mod config;
pub mod discovery;
pub mod io;
pub mod path;

use crate::types::ProcessorMode;
use anyhow::Result;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use config::FileConfig;
use discovery::Discovery;

/// FileManager handles file system operations including finding eligible files,
/// managing paths, and performing file I/O.
///
/// This struct acts as a facade providing a cohesive API for file operations
/// needed during encryption and decryption workflows.
pub struct FileManager {
    discovery: Discovery,
}

impl FileManager {
    /// Creates a new FileManager instance with default configuration.
    pub fn new() -> Self {
        Self {
            discovery: Discovery::new(FileConfig::default()),
        }
    }

    /// Finds files eligible for the given processing mode.
    ///
    /// # Errors
    ///
    /// Returns an error if directory traversal fails.
    pub fn find_eligible_files(&self, mode: ProcessorMode) -> Result<Vec<PathBuf>> {
        self.discovery.find_eligible_files(mode)
    }

    /// Determines the output path based on input path and mode.
    ///
    /// For encryption, appends the file extension to the input path.
    /// For decryption, removes the file extension if present.
    pub fn get_output_path(&self, input_path: &Path, mode: ProcessorMode) -> PathBuf {
        path::get_output_path(input_path, mode)
    }

    /// Removes a file if it exists.
    ///
    /// This is safe to call even if the file doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be deleted.
    pub fn remove(&self, path: &Path) -> Result<()> {
        io::remove(path)
    }

    /// Opens a file and returns the file handle and metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or metadata cannot be read.
    pub fn open_file(&self, path: &Path) -> Result<(File, fs::Metadata)> {
        io::open_file(path)
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
    /// Returns an error if validation fails.
    pub fn validate_path(&self, path: &Path, must_exist: bool) -> Result<()> {
        path::validate_path(path, must_exist)
    }
}

impl Default for FileManager {
    fn default() -> Self {
        Self::new()
    }
}
