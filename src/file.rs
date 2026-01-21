//! File discovery and operations.
//!
//! Provides the [`File`] struct for managing file paths, metadata,
//! and I/O operations. Includes file discovery via directory traversal
//! with pattern-based exclusion.
//!
//! # File Discovery
//!
//! Files are discovered recursively starting from the current directory.
//! Certain patterns and hidden files are excluded by default:
//!
//! - Files starting with `.` (hidden files)
//! - Files matching patterns in [`EXCLUDED_PATTERNS`]
//! - Files that don't match the processing mode (e.g., already encrypted when encrypting)
//!
//! # Output Path Generation
//!
//! - For encryption: appends `.swx` extension
//! - For decryption: removes `.swx` extension if present

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use fast_glob::glob_match;
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

/// Lazy-initialized exclusion pattern matchers.
///
/// This static is initialized once on first access using `LazyLock`.
/// The patterns from config are converted from `&str` to `String`
/// to enable ownership-based pattern matching with `glob_match`.
/// This avoids repeated allocations during file filtering operations.
static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| {
    // Iterate over exclusion patterns from config
    // Convert each &str to owned String for pattern matching
    EXCLUDED_PATTERNS.iter().map(|s| (*s).to_owned()).collect()
});

/// Represents a file with metadata and helper methods.
///
/// This struct wraps a filesystem path and provides convenience methods
/// for common file operations. It caches file size to avoid repeated
/// filesystem metadata queries.
///
/// # Thread Safety
///
/// This struct is Clone + Send + Sync safe for use in concurrent contexts,
/// though mutable operations (like size query) require mutable references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The file path as a PathBuf.
    ///
    /// PathBuf allows efficient path manipulation and is the standard
    /// Rust type for owning filesystem paths.
    path: PathBuf,

    /// Cached file size in bytes.
    ///
    /// `None` indicates the size has not been queried yet.
    /// Once queried, the size is cached here to avoid repeated
    /// filesystem metadata queries, which can be expensive.
    /// This field is mutable to allow caching on first size() call.
    size: Option<u64>,

    /// Selection state for interactive file picking.
    ///
    /// Used by the UI to track which files the user has selected
    /// in multi-select scenarios. Set to `true` by default.
    is_selected: bool,
}

impl File {
    /// Creates a new file reference from a path.
    ///
    /// This method accepts any type that can be converted into a PathBuf,
    /// including `String`, `&str`, `PathBuf`, and `Path`. The conversion
    /// happens via the `Into<PathBuf>` trait bound.
    ///
    /// # Arguments
    ///
    /// * `path` - The file system path (can be `String`, `&str`, or `PathBuf`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        // Convert input to PathBuf and initialize struct
        // is_selected defaults to true for interactive selection
        Self { path: path.into(), size: None, is_selected: true }
    }

    /// Returns a reference to the file path.
    ///
    /// This is a simple accessor that returns a borrowed reference
    /// to the internal PathBuf. The lifetime is tied to self.
    ///
    /// # Returns
    ///
    /// A reference to the file path.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gets the file size in bytes.
    ///
    /// This method queries the filesystem for the file's metadata
    /// and returns the file size. The result is cached internally
    /// to avoid repeated metadata queries on subsequent calls.
    ///
    /// # Caching Behavior
    ///
    /// - First call: queries filesystem, caches result, returns size
    /// - Subsequent calls: returns cached size without filesystem access
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist (ENOENT)
    /// - Permission denied
    /// - Other filesystem errors accessing metadata
    pub fn size(&mut self) -> Result<u64> {
        // Check if size is already cached from a previous call
        // If so, return the cached value immediately without filesystem access
        if let Some(size) = self.size {
            return Ok(size);
        }

        // Size not cached, need to query filesystem
        // fs::metadata() returns metadata about the file
        // This includes file size, permissions, modification time, etc.
        // The path is displayed in error context for debugging
        let meta = fs::metadata(&self.path).with_context(|| format!("failed to get metadata: {}", self.path.display()))?;

        // Cache the size for future calls
        // meta.len() returns the file size in bytes as u64
        self.size = Some(meta.len());

        // Return the size
        Ok(meta.len())
    }

    /// Checks if the file has a `.swx` extension.
    ///
    /// This is used to identify already-encrypted files by checking
    /// if the filename ends with the SweetByte encrypted file extension.
    ///
    /// # Implementation Details
    ///
    /// - Converts OS string to lossily UTF-8 representation
    /// - Uses Rust's str::ends_with() for extension matching
    /// - The FILE_EXTENSION constant is ".swx"
    ///
    /// # Returns
    ///
    /// `true` if the file has `.swx` extension, `false` otherwise.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        // to_string_lossy() converts OsStr to a lossy UTF-8 String
        // This handles paths that may contain non-UTF8 characters
        // ends_with() checks if the string ends with the extension
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    /// Checks if the file is hidden (starts with `.`).
    ///
    /// On Unix-like systems, files starting with a dot are considered
    /// hidden files. This method checks if the filename (not the full path)
    /// starts with a dot.
    ///
    /// # Implementation Details
    ///
    /// - Gets just the filename/directory name component
    /// - Checks if that component starts with '.'
    /// - Uses is_some_and() for safe optional handling
    ///
    /// # Returns
    ///
    /// `true` if the file is hidden, `false` otherwise.
    #[inline]
    pub fn is_hidden(&self) -> bool {
        // path.file_name() returns the final component of the path
        // Some if there's a filename, None if path is root or empty
        // is_some_and() returns true if Some and the closure returns true
        self.path.file_name().is_some_and(|name| {
            // Convert to string and check if first character is '.'
            name.to_string_lossy().starts_with('.')
        })
    }

    /// Checks if the file matches any exclusion pattern.
    ///
    /// This method checks both the full path and individual path components
    /// against a list of exclusion patterns. Patterns use glob-style matching
    /// (e.g., "*.rs" matches Rust files, "target" matches directory names).
    ///
    /// # Exclusion Patterns
    ///
    /// - File names: "*.rs", "*.go" (source files)
    /// - Directory names: "target", "node_modules", ".git"
    /// - Sensitive directories: ".ssh", ".gnupg"
    ///
    /// # Matching Strategy
    ///
    /// 1. Check if full path matches any pattern
    /// 2. Check each path component (directory names) against patterns
    /// 3. Return true if any match is found (file is excluded)
    pub fn is_excluded(&self) -> bool {
        // Convert path to string for pattern matching
        // Use empty string as fallback if path contains invalid UTF-8
        let path_str = self.path.to_str().unwrap_or("");

        // Check full path and each component against exclusion patterns
        // Uses short-circuit evaluation: if any pattern matches, return true
        EXCLUSION_MATCHERS.iter().any(|pattern| {
            // glob_match() returns true if the path matches the pattern
            // Check full path first
            let full_match = glob_match(pattern, path_str);

            if full_match {
                // Full path matches, file is excluded
                return true;
            }

            // Check each path component separately
            // This catches patterns like "target" in "/home/user/target/file.txt"
            // path.components() iterates over: "home", "user", "target", "file.txt"
            self.path.components().any(|comp| {
                // Convert component to string for pattern matching
                // comp.as_os_str() gets the OS string representation
                // to_str() converts to UTF-8 Option
                // unwrap_or("") handles invalid UTF-8
                glob_match(pattern, comp.as_os_str().to_str().unwrap_or(""))
            })
        })
    }

    /// Checks if the file is eligible for the specified processing mode.
    ///
    /// A file is eligible if it passes all the following checks:
    /// 1. Not a hidden file (doesn't start with '.')
    /// 2. Doesn't match any exclusion pattern
    /// 3. Matches the mode's file type requirement:
    ///    - Encrypt: file must NOT be encrypted (no .swx extension)
    ///    - Decrypt: file MUST be encrypted (has .swx extension)
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode to check eligibility for.
    ///
    /// # Returns
    ///
    /// `true` if the file is eligible for the given mode, `false` otherwise.
    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        // First, check if file should be excluded entirely
        // Skip hidden files (starting with '.') and excluded patterns
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        // Check mode-specific requirements
        match mode {
            // Encryption mode: skip files that are already encrypted
            // This prevents double-encryption of .swx files
            ProcessorMode::Encrypt => !self.is_encrypted(),
            // Decryption mode: only process files with .swx extension
            // This ensures we only try to decrypt valid encrypted files
            ProcessorMode::Decrypt => self.is_encrypted(),
        }
    }

    /// Generates the output path for a processed file.
    ///
    /// For encryption, the output path is the input path with `.swx` appended.
    /// For decryption, the output path is the input path with `.swx` removed.
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode.
    ///
    /// # Returns
    ///
    /// A PathBuf containing the output file path.
    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            // Encryption: append .swx extension to the filename
            ProcessorMode::Encrypt => {
                // Get the OS string representation of the path
                let mut name = self.path.as_os_str().to_os_string();
                // Push the extension (adds ".swx")
                name.push(FILE_EXTENSION);
                // Convert back to PathBuf
                PathBuf::from(name)
            }
            // Decryption: remove .swx extension if present
            ProcessorMode::Decrypt => {
                // Convert path to string for string operations
                // strip_suffix() removes ".swx" if the path ends with it
                // map_or_else() handles the case where .swx is not present:
                //   - If stripped: return the stripped PathBuf
                //   - If not stripped: return a clone of the original path
                self.path.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(
                    || self.path.clone(), // No .swx suffix, use original path
                    PathBuf::from,        // Stripped .swx, convert stripped string to PathBuf
                )
            }
        }
    }

    /// Checks if the file exists on the filesystem.
    ///
    /// This is a simple wrapper around `Path::exists()`.
    ///
    /// # Returns
    ///
    /// `true` if the file exists, `false` otherwise.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Checks if the path is a directory.
    ///
    /// This is a simple wrapper around `Path::is_dir()`.
    ///
    /// # Returns
    ///
    /// `true` if the path is a directory, `false` otherwise.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Creates a buffered reader for reading the file contents.
    ///
    /// This method opens the file for reading and wraps it in a BufReader,
    /// which provides buffering for more efficient I/O operations.
    ///
    /// # Buffering Benefits
    ///
    /// - Reduces number of system calls for small reads
    /// - Improves read throughput for sequential access
    /// - Default buffer size is typically 8KB
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File doesn't exist (ENOENT)
    /// - Permission denied (EACCES)
    /// - File is a directory (EISDIR)
    /// - Other I/O errors opening the file
    pub fn reader(&self) -> Result<BufReader<fs::File>> {
        // fs::File::open() opens a file in read-only mode
        // Returns a fs::File handle on success
        // Wraps error context with the file path for debugging
        let file = fs::File::open(&self.path).with_context(|| format!("failed to open file: {}", self.path.display()))?;

        // Wrap in BufReader for buffered reading
        // BufReader improves I/O performance by buffering reads
        Ok(BufReader::new(file))
    }

    /// Creates a buffered writer for writing to the file.
    ///
    /// This method creates or opens a file for writing and wraps it in a BufWriter.
    /// Parent directories are created if they don't exist.
    ///
    /// # File Creation Behavior
    ///
    /// - If file doesn't exist: creates it
    /// - If file exists: truncates it to zero length (overwrites)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parent directory cannot be created
    /// - File cannot be opened for writing
    /// - Permission denied
    pub fn writer(&self) -> Result<BufWriter<fs::File>> {
        // Check if parent directory exists and create if needed
        // self.path.parent() returns Some(parent) if there's a parent directory
        // The filter ensures we skip empty parents (e.g., "/file.txt" has no parent)
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            // fs::create_dir_all() recursively creates directories
            // It succeeds if the directory already exists
            // Wraps error context with parent path for debugging
            fs::create_dir_all(parent).with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        // Create file handle with write, create, and truncate options
        // fs::OpenOptions provides fine-grained control over file opening
        let file = fs::OpenOptions::new()
            .write(true) // Open for writing
            .create(true) // Create if doesn't exist
            .truncate(true) // Truncate existing file to zero length
            .open(&self.path) // Attempt to open/create the file
            .with_context(|| format!("failed to create file: {}", self.path.display()))?;

        // Wrap in BufWriter for buffered writing
        // BufWriter improves I/O performance by buffering writes
        Ok(BufWriter::new(file))
    }

    /// Deletes the file from the filesystem.
    ///
    /// This method removes the file using `fs::remove_file()`.
    /// Note that this is not a secure delete - the data may still
    /// be recoverable from the disk. For secure deletion, the file
    /// should be overwritten before deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File doesn't exist
    /// - Permission denied
    /// - File is a directory (use fs::remove_dir() instead)
    pub fn delete(&self) -> Result<()> {
        // First check that file exists (provides better error message)
        ensure!(self.exists(), "file not found: {}", self.path.display());

        // Remove the file
        // This unlinks the file from the filesystem
        // The actual disk blocks may or may not be freed immediately
        // depending on the filesystem and operating system
        fs::remove_file(&self.path).with_context(|| format!("failed to delete file: {}", self.path.display()))
    }

    /// Validates the file according to specified constraints.
    ///
    /// This method performs various validation checks depending on the
    /// `must_exist` parameter. It's used to validate input files before
    /// processing and output files before writing.
    ///
    /// # Validation Checks (must_exist = true)
    ///
    /// 1. File exists (not missing)
    /// 2. Path is not a directory (must be a regular file)
    /// 3. File has non-zero size (not empty)
    ///
    /// # Validation Checks (must_exist = false)
    ///
    /// 1. File does NOT exist (for output validation)
    ///
    /// # Arguments
    ///
    /// * `must_exist` - If `true`, validates the file exists and is a non-empty file.
    ///   If `false`, validates the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails:
    /// - File not found when `must_exist` is `true`
    /// - Path is a directory when `must_exist` is `true`
    /// - File is empty when `must_exist` is `true`
    /// - File already exists when `must_exist` is `false`
    pub fn validate(&mut self, must_exist: bool) -> Result<()> {
        if must_exist {
            // Validation for input files: must exist and be valid
            ensure!(self.exists(), "file not found: {}", self.path.display());
            ensure!(!self.is_dir(), "path is a directory: {}", self.path.display());

            // Get file size (also performs existence check implicitly)
            let size = self.size()?;
            ensure!(size != 0, "file is empty: {}", self.path.display());
        } else {
            // Validation for output files: must NOT exist
            ensure!(!self.exists(), "file already exists: {}", self.path.display());
        }

        Ok(())
    }

    /// Discovers files in the current directory and subdirectories.
    ///
    /// This method uses WalkDir to recursively traverse the current
    /// directory and its subdirectories, finding all regular files
    /// that match the given processing mode's eligibility criteria.
    ///
    /// # Discovery Process
    ///
    /// 1. WalkDir starts from "." (current directory)
    /// 2. Each entry is processed through a chain of filters
    /// 3. Valid entries are converted to File instances
    /// 4. Files are filtered by eligibility for the mode
    ///
    /// # Filtering Steps
    ///
    /// 1. filter_map: Skip entries that can't be read (permission errors, etc.)
    /// 2. filter: Only keep regular files (not directories, symlinks, etc.)
    /// 3. map: Convert WalkDir entries to File instances
    /// 4. filter: Keep only files eligible for the processing mode
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode to filter eligible files.
    ///
    /// # Returns
    ///
    /// A vector of eligible File instances, sorted by path.
    /// The WalkDir iterator naturally yields entries in sorted order.
    pub fn discover(mode: ProcessorMode) -> Vec<Self> {
        // Create a new WalkDir iterator starting from current directory
        // WalkDir recursively traverses directories
        WalkDir::new(".")
            .into_iter() // Convert to iterator over WalkDirEntry
            // Step 1: Skip entries that couldn't be read
            // entry.ok() returns Some(entry) on success, None on error
            .filter_map(|entry| entry.ok())
            // Step 2: Only keep regular files (not directories)
            // is_file() returns true for regular files
            .filter(|entry| entry.file_type().is_file())
            // Step 3: Convert WalkDirEntry to File instance
            // into_path() consumes the entry and returns the PathBuf
            .map(|entry| Self::new(entry.into_path()))
            // Step 4: Filter by eligibility for the processing mode
            // is_eligible() checks encryption status, hidden status, exclusion patterns
            .filter(|file| file.is_eligible(mode))
            // Collect all matching files into a Vec
            .collect()
    }
}
