//! File system operations and discovery.
//!
//! This module handles file discovery, validation, metadata extraction, and safe I/O operations.
//! It serves as the bridge between the high-level processing logic and the OS file system.
//!
//! # Features
//!
//! - **Recursive Discovery**: Finds eligible files in directories.
//! - **Filtering**: Excludes hidden files and matches specific patterns (e.g., git directories).
//! - **Validation**: Ensures files exist, are readable, and are not empty.
//! - **Path Management**: Derives output filenames (e.g., adding/removing `.swx` extension).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use fast_glob::glob_match;
use tokio::fs;
use tokio::io::{BufReader, BufWriter};
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

/// Pre-compiled list of exclusion patterns.
///
/// We use `LazyLock` to parse the exclusion patterns once at startup,
/// avoiding redundant allocation during file traversal.
static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| EXCLUDED_PATTERNS.iter().map(|s| (*s).to_owned()).collect());

/// Represents a file on the filesystem with its processing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The absolute or relative path to the file.
    path: PathBuf,

    /// Cached file size in bytes (populated lazily).
    size: Option<u64>,

    /// Whether this file is selected for processing.
    /// (Currently defaults to true, potentially useful for UI selection).
    is_selected: bool,
}

impl File {
    /// Creates a new `File` instance from a path.
    ///
    /// The file size is not queried immediately to avoid unnecessary I/O during
    /// the discovery phase of large directories.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None, is_selected: true }
    }

    /// Returns a reference to the file path.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the file size, querying the filesystem if not already cached.
    ///
    /// # Errors
    ///
    /// Returns an error if the file metadata cannot be read (e.g., permission denied).
    pub async fn size(&mut self) -> Result<u64> {
        // Return cached value if available to avoid syscall.
        if let Some(size) = self.size {
            return Ok(size);
        }

        // Fetch metadata from OS.
        let meta = fs::metadata(&self.path).await.with_context(|| format!("failed to get metadata: {}", self.path.display()))?;

        // Cache and return.
        self.size = Some(meta.len());
        Ok(meta.len())
    }

    /// Retrieves both the filename and size.
    ///
    /// Useful for UI display or header creation.
    ///
    /// # Returns
    ///
    /// A tuple `(filename, size)`. If the filename is not valid UTF-8, returns "unknown".
    pub async fn file_metadata(&self) -> Result<(String, u64)> {
        let meta = fs::metadata(&self.path).await.with_context(|| format!("failed to get metadata: {}", self.path.display()))?;

        // lossy conversion handles non-UTF8 filenames gracefully.
        let filename = self.path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "unknown".to_owned());

        let size = meta.len();

        Ok((filename, size))
    }

    /// Checks if the file has the encrypted extension (`.swx`).
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    /// Checks if the file is hidden (starts with `.`).
    #[inline]
    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    /// Checks if the file matches any exclusion patterns.
    ///
    /// Returns `true` if the file path matches patterns like `.git`, `target`, etc.
    pub fn is_excluded(&self) -> bool {
        let path_str = self.path.to_str().unwrap_or("");

        // Iterate through all exclusion patterns.
        EXCLUSION_MATCHERS.iter().any(|pattern| {
            // Check if the full path matches the pattern directly.
            let full_match = glob_match(pattern, path_str);
            if full_match {
                return true;
            }

            // Check if any individual component of the path matches.
            // This handles cases like excluding "node_modules" appearing anywhere in the tree.
            self.path.components().any(|comp| glob_match(pattern, comp.as_os_str().to_str().unwrap_or("")))
        })
    }

    /// Determines if the file should be processed based on the current mode.
    ///
    /// # Logic
    ///
    /// - Returns `false` if hidden or excluded.
    /// - **Encrypt Mode**: Returns `true` only if the file is *not* already encrypted.
    /// - **Decrypt Mode**: Returns `true` only if the file *is* encrypted.
    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        // Skip hidden and excluded files to prevent accidental processing of system files.
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        match mode {
            // Can't re-encrypt an already encrypted file (avoid double encryption).
            ProcessorMode::Encrypt => !self.is_encrypted(),
            // Can only decrypt files that have the correct extension.
            ProcessorMode::Decrypt => self.is_encrypted(),
        }
    }

    /// Determines the output path based on the operation mode.
    ///
    /// - **Encrypt**: Appends `.swx` (e.g., `doc.txt` -> `doc.txt.swx`).
    /// - **Decrypt**: Removes `.swx` (e.g., `doc.txt.swx` -> `doc.txt`).
    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            ProcessorMode::Encrypt => {
                let mut name = self.path.as_os_str().to_os_string();
                name.push(FILE_EXTENSION);
                PathBuf::from(name)
            }
            ProcessorMode::Decrypt => {
                // Try to strip the extension.
                // If it fails (shouldn't if verified), return original path (failsafe).
                self.path.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(|| self.path.clone(), PathBuf::from)
            }
        }
    }

    /// Checks if the file exists on disk.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Checks if the path points to a directory.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Opens the file for reading with a buffered reader.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub async fn reader(&self) -> Result<BufReader<fs::File>> {
        let file = fs::File::open(&self.path).await.with_context(|| format!("failed to open file: {}", self.path.display()))?;

        Ok(BufReader::new(file))
    }

    /// Opens the file for writing (creating/truncating it) with a buffered writer.
    ///
    /// Automatically creates parent directories if they don't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file opening fails.
    pub async fn writer(&self) -> Result<BufWriter<fs::File>> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).await.with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        // Open with create/write/truncate flags.
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .await
            .with_context(|| format!("failed to create file: {}", self.path.display()))?;

        Ok(BufWriter::new(file))
    }

    /// Deletes the file from the filesystem.
    ///
    /// Used during cleanup or when replacing original files.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or cannot be removed.
    pub async fn delete(&self) -> Result<()> {
        ensure!(self.exists(), "file not found: {}", self.path.display());

        fs::remove_file(&self.path).await.with_context(|| format!("failed to delete file: {}", self.path.display()))
    }

    /// Validates the file state based on requirements.
    ///
    /// # Arguments
    ///
    /// * `must_exist` - If true, ensures file exists, is not a dir, and is not empty. If false,
    ///   ensures file does *not* exist (to prevent overwrite).
    pub async fn validate(&mut self, must_exist: bool) -> Result<()> {
        if must_exist {
            ensure!(self.exists(), "file not found: {}", self.path.display());
            ensure!(!self.is_dir(), "path is a directory: {}", self.path.display());

            let size = self.size().await?;
            ensure!(size != 0, "file is empty: {}", self.path.display());
        } else {
            ensure!(!self.exists(), "file already exists: {}", self.path.display());
        }

        Ok(())
    }

    /// Discovers eligible files in the current directory recursively.
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode (Encrypt/Decrypt) used to filter eligibility.
    ///
    /// # Returns
    ///
    /// A vector of valid `File` objects.
    pub fn discover(mode: ProcessorMode) -> Vec<Self> {
        // WalkDir traverses recursively.
        WalkDir::new(".")
            .into_iter()
            // Ignore permission errors during traversal.
            .filter_map(|entry| entry.ok())
            // Only care about files, not directories (directories are just containers).
            .filter(|entry| entry.file_type().is_file())
            // Wrap in our File struct.
            .map(|entry| Self::new(entry.into_path()))
            // Apply filtering logic (hidden, excluded, encrypted status).
            .filter(|file| file.is_eligible(mode))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_new() {
        let f = File::new("test.txt");
        assert_eq!(f.path(), Path::new("test.txt"));
    }

    #[test]
    fn test_is_encrypted() {
        let f = File::new("test.txt");
        assert!(!f.is_encrypted());

        let f_enc = File::new("test.txt.swx");
        assert!(f_enc.is_encrypted());
    }

    #[test]
    fn test_is_hidden() {
        let f = File::new(".hidden");
        assert!(f.is_hidden());

        let f_visible = File::new("visible");
        assert!(!f_visible.is_hidden());
    }

    #[test]
    fn test_output_path_encrypt() {
        let f = File::new("test.txt");
        let out = f.output_path(ProcessorMode::Encrypt);
        assert_eq!(out, PathBuf::from("test.txt.swx"));
    }

    #[test]
    fn test_output_path_decrypt() {
        let f = File::new("test.txt.swx");
        let out = f.output_path(ProcessorMode::Decrypt);
        assert_eq!(out, PathBuf::from("test.txt"));

        let f2 = File::new("test.txt");
        let out2 = f2.output_path(ProcessorMode::Decrypt);
        assert_eq!(out2, PathBuf::from("test.txt"));
    }

    #[test]
    fn test_is_eligible_encrypt() {
        let f = File::new("test.txt");
        assert!(f.is_eligible(ProcessorMode::Encrypt));

        let f_hidden = File::new(".test");
        assert!(!f_hidden.is_eligible(ProcessorMode::Encrypt));

        let f_enc = File::new("test.txt.swx");
        assert!(!f_enc.is_eligible(ProcessorMode::Encrypt));
    }

    #[test]
    fn test_is_eligible_decrypt() {
        let f = File::new("test.txt.swx");
        assert!(f.is_eligible(ProcessorMode::Decrypt));

        let f_plain = File::new("test.txt");
        assert!(!f_plain.is_eligible(ProcessorMode::Decrypt));
    }
}
