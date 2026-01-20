use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use fast_glob::glob_match;
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

/// Lazily initialized exclusion matchers for file discovery.
///
/// Converts the static EXCLUDED_PATTERNS into a Vec<String> for efficient
/// matching during file discovery operations.
static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| EXCLUDED_PATTERNS.iter().map(|s| (*s).to_owned()).collect());

/// Represents a file in the SweetByte encryption system.
///
/// This struct wraps a filesystem path and provides methods for file operations
/// including validation, discovery, reading, writing, and deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The filesystem path to the file.
    path: PathBuf,
    /// Cached file size in bytes, populated on first access.
    size: Option<u64>,
    /// Whether this file is selected for processing.
    is_selected: bool,
}

impl File {
    /// Creates a new File instance with the given path.
    ///
    /// # Arguments
    /// * `path` - The filesystem path, which can be any type implementing `Into<PathBuf>`.
    ///
    /// # Returns
    /// A new File instance with the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None, is_selected: true }
    }

    /// Returns an immutable reference to the file path.
    ///
    /// # Returns
    /// A reference to the underlying Path.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gets the file size in bytes.
    ///
    /// Caches the size after the first call to avoid repeated filesystem queries.
    ///
    /// # Returns
    /// The file size in bytes, or an error if the file doesn't exist or is inaccessible.
    pub fn size(&mut self) -> Result<u64> {
        // Return cached size if available.
        if let Some(size) = self.size {
            return Ok(size);
        }

        // Query filesystem metadata and cache the result.
        let meta = fs::metadata(&self.path).with_context(|| format!("failed to get metadata: {}", self.path.display()))?;
        self.size = Some(meta.len());
        Ok(meta.len())
    }

    /// Checks if the file has the encrypted file extension.
    ///
    /// A file is considered encrypted if its path ends with `.swx`.
    ///
    /// # Returns
    /// True if the file appears to be encrypted, false otherwise.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    /// Checks if the file is hidden (starts with a dot).
    ///
    /// # Returns
    /// True if the filename starts with '.', false otherwise.
    #[inline]
    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    /// Checks if the file path matches any exclusion patterns.
    ///
    /// Exclusion patterns include common directories like `target`, `node_modules`,
    /// `.git`, and file extensions like `*.rs`, `*.go`.
    ///
    /// # Returns
    /// True if the file matches any exclusion pattern.
    pub fn is_excluded(&self) -> bool {
        let path_str = self.path.to_str().unwrap_or("");

        // Check against full path and individual path components.
        EXCLUSION_MATCHERS
            .iter()
            .any(|pattern| glob_match(pattern, path_str) || self.path.components().any(|comp| glob_match(pattern, comp.as_os_str().to_str().unwrap_or(""))))
    }

    /// Checks if the file is eligible for the given processing mode.
    ///
    /// A file is eligible if it's not hidden, not excluded, and matches the
    /// encryption state expected by the mode (unencrypted for encrypt, encrypted for decrypt).
    ///
    /// # Arguments
    /// * `mode` - The processor mode to check eligibility against.
    ///
    /// # Returns
    /// True if the file is eligible for the specified mode.
    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        // Exclude hidden and excluded files.
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        match mode {
            ProcessorMode::Encrypt => !self.is_encrypted(),
            ProcessorMode::Decrypt => self.is_encrypted(),
        }
    }

    /// Computes the output path for the processed file.
    ///
    /// For encryption, appends the `.swx` extension. For decryption, removes
    /// the `.swx` extension if present.
    ///
    /// # Arguments
    /// * `mode` - The processor mode to determine output naming.
    ///
    /// # Returns
    /// The PathBuf for the output file.
    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            ProcessorMode::Encrypt => {
                // Append .swx extension to the original filename.
                let mut name = self.path.as_os_str().to_os_string();
                name.push(FILE_EXTENSION);
                PathBuf::from(name)
            }
            ProcessorMode::Decrypt => {
                // Strip .swx extension if present, otherwise return original path.
                self.path.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(|| self.path.clone(), PathBuf::from)
            }
        }
    }

    /// Checks if the file exists on the filesystem.
    ///
    /// # Returns
    /// True if the path exists, false otherwise.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Checks if the path is a directory.
    ///
    /// # Returns
    /// True if the path is a directory, false otherwise.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Opens the file for reading and returns a buffered reader.
    ///
    /// # Returns
    /// A BufReader wrapping the opened file, or an error if the file cannot be opened.
    pub fn reader(&self) -> Result<BufReader<fs::File>> {
        let file = fs::File::open(&self.path).with_context(|| format!("failed to open file: {}", self.path.display()))?;
        Ok(BufReader::new(file))
    }

    /// Opens the file for writing, creating parent directories if needed.
    ///
    /// Creates the parent directory structure if it doesn't exist, then opens
    /// the file with write, create, and truncate options.
    ///
    /// # Returns
    /// A BufWriter wrapping the opened file, or an error if creation failed.
    pub fn writer(&self) -> Result<BufWriter<fs::File>> {
        // Create parent directories if needed.
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        // Open file with write, create, and truncate options.
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .with_context(|| format!("failed to create file: {}", self.path.display()))?;

        Ok(BufWriter::new(file))
    }

    /// Deletes the file from the filesystem.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the file cannot be deleted.
    pub fn delete(&self) -> Result<()> {
        ensure!(self.exists(), "file not found: {}", self.path.display());

        fs::remove_file(&self.path).with_context(|| format!("failed to delete file: {}", self.path.display()))
    }

    /// Validates the file according to the specified requirements.
    ///
    /// If `must_exist` is true, validates that the file exists, is not a directory,
    /// and is not empty. If `must_exist` is false, validates that the file does not exist.
    ///
    /// # Arguments
    /// * `must_exist` - If true, validates existence; if false, validates non-existence.
    ///
    /// # Returns
    /// Ok(()) if validation passes, or an error if validation fails.
    pub fn validate(&mut self, must_exist: bool) -> Result<()> {
        if must_exist {
            // Validate existence and file properties.
            ensure!(self.exists(), "file not found: {}", self.path.display());
            ensure!(!self.is_dir(), "path is a directory: {}", self.path.display());

            let size = self.size()?;
            ensure!(size != 0, "file is empty: {}", self.path.display());
        } else {
            // Validate that file does not exist.
            ensure!(!self.exists(), "file already exists: {}", self.path.display());
        }

        Ok(())
    }

    /// Discovers eligible files in the current directory tree.
    ///
    /// Walks the current directory, filters for regular files, and returns
    /// only those eligible for the specified processing mode.
    ///
    /// # Arguments
    /// * `mode` - The processor mode to filter eligible files.
    ///
    /// # Returns
    /// A Vec of eligible File instances.
    pub fn discover(mode: ProcessorMode) -> Vec<Self> {
        WalkDir::new(".")
            .into_iter()
            // Filter out entries that couldn't be read.
            .filter_map(|entry| entry.ok())
            // Keep only regular files.
            .filter(|entry| entry.file_type().is_file())
            // Convert to File instances.
            .map(|entry| Self::new(entry.into_path()))
            // Filter by eligibility.
            .filter(|file| file.is_eligible(mode))
            .collect()
    }
}
