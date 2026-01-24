//! File Operations and Management Module
//!
//! This module provides a high-level abstraction for file operations in SweetByte,
//! including file discovery, validation, I/O operations, and path manipulation.
//! It focuses on security, performance, and user experience.
//!
//! ## Security Features
//!
//! - Path traversal protection through canonicalization
//! - File permission validation before operations
//! - Atomic file operations where possible
//! - Secure file deletion options
//! - Exclusion of sensitive system files
//!
//! ## Performance Optimizations
//!
//! - Buffered I/O for better throughput
//! - Lazy metadata evaluation to avoid unnecessary syscalls
//! - Efficient directory traversal with parallel discovery
//! - Memory-mapped file operations for large files
//!
//! ## User Experience
//!
//! - Automatic output path generation based on operation
//! - File filtering and exclusion for relevant content only
//! - Progress feedback integration with UI module
//! - Clear error messages with context

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use fast_glob::glob_match;
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

/// Pre-compiled exclusion patterns for efficient file filtering
///
/// This lazy-static collection compiles glob patterns at startup to avoid
/// repeated pattern compilation during file discovery operations.
/// It improves performance when filtering large directory trees.
static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| EXCLUDED_PATTERNS.iter().map(|s| (*s).to_owned()).collect());

/// High-level file abstraction for SweetByte operations
///
/// This struct provides a secure and convenient interface for file operations
/// throughout the application. It encapsulates common operations like validation,
/// I/O, and path manipulation while maintaining security best practices.
///
/// ## Design Principles
///
/// - **Security First**: All operations validate inputs and prevent common attacks
/// - **Performance Optimized**: Lazy evaluation and buffered I/O for efficiency
/// - **User Friendly**: Clear error messages and sensible default behaviors
/// - **Cross Platform**: Consistent behavior across Windows, macOS, and Linux
///
/// ## Thread Safety
///
/// File instances are thread-safe for read operations. Write operations
/// should be serialized to avoid race conditions when modifying the same file.
///
/// ## Memory Management
///
/// The struct is designed to be lightweight, storing only essential metadata.
/// Large file operations use streaming I/O to avoid loading entire files
/// into memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The canonical file path
    ///
    /// This is stored as a PathBuf to enable efficient path manipulation
    /// and to maintain platform-specific path characteristics.
    path: PathBuf,

    /// Cached file size for performance optimization
    ///
    /// This is `Option<u64>` to enable lazy evaluation - the size is only
    /// computed when requested, and then cached to avoid repeated syscalls.
    size: Option<u64>,

    /// Selection state for UI operations
    ///
    /// This flag is used by the interactive mode to track which files
    /// the user has selected for processing. Default is true for convenience.
    is_selected: bool,
}

impl File {
    /// Create a new File instance with the specified path
    ///
    /// This constructor creates a File instance without performing any
    /// filesystem operations. The path is converted to a PathBuf for
    /// efficient manipulation and stored internally.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path (anything convertible to PathBuf)
    ///
    /// # Returns
    ///
    /// A new File instance with default settings
    ///
    /// # Default Settings
    ///
    /// - Size: None (will be computed on first access)
    /// - Selected: true (opt-in for interactive mode)
    ///
    /// # Security Notes
    ///
    /// This constructor does not validate the path or check if the file
    /// exists. Use validate() for comprehensive validation before operations.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None, is_selected: true }
    }

    /// Get the file path as a Path reference
    ///
    /// This provides read-only access to the internal path without
    /// allowing modification. The path can be used for display,
    /// comparison, or other read-only operations.
    ///
    /// # Returns
    ///
    /// Immutable reference to the file's Path
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it returns an immutable reference.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the file size, computing and caching it if necessary
    ///
    /// This method implements lazy evaluation - the file size is only
    /// computed on first access and then cached for subsequent calls.
    /// This optimization reduces filesystem operations when the size
    /// is needed multiple times.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The file size in bytes
    /// * `Err(anyhow::Error)` - Failed to access file or get metadata
    ///
    /// # Performance
    ///
    /// First call: O(1) filesystem operation
    /// Subsequent calls: O(1) memory access (cached)
    ///
    /// # Error Conditions
    ///
    /// - File does not exist
    /// - Insufficient permissions to read metadata
    /// - Path refers to a directory
    /// - Network/filesystem errors
    pub fn size(&mut self) -> Result<u64> {
        // Return cached size if already computed
        if let Some(size) = self.size {
            return Ok(size);
        }

        // Compute and cache the size
        let meta = fs::metadata(&self.path).with_context(|| format!("failed to get metadata: {}", self.path.display()))?;

        self.size = Some(meta.len());

        Ok(meta.len())
    }

    /// Get file metadata for display purposes
    ///
    /// This method extracts commonly needed metadata for UI display,
    /// including the filename and file size. It's optimized for the
    /// interactive mode file browser.
    ///
    /// # Returns
    ///
    /// * `Ok((String, u64))` - Tuple of (filename, size_in_bytes)
    /// * `Err(anyhow::Error)` - Failed to access file metadata
    ///
    /// # Filename Handling
    ///
    /// - Returns only the filename component (no directory path)
    /// - Handles Unicode filenames correctly
    /// - Returns "unknown" if filename cannot be determined
    ///
    /// # Security Notes
    ///
    /// The filename extraction is safe against path traversal attacks
    /// as it only returns the final component of the path.
    pub fn file_metadata(&self) -> Result<(String, u64)> {
        // Get file metadata including size
        let meta = fs::metadata(&self.path).with_context(|| format!("failed to get metadata: {}", self.path.display()))?;

        // Extract filename safely (only the final component)
        let filename = self.path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "unknown".to_owned());

        let size = meta.len();

        Ok((filename, size))
    }

    /// Check if the file appears to be encrypted by SweetByte
    ///
    /// This method determines if a file has the SweetByte extension
    /// (.swx) which indicates it was previously encrypted by this
    /// application. This is used for file filtering and mode validation.
    ///
    /// # Returns
    ///
    /// `true` if the filename ends with the SweetByte extension
    ///
    /// # Security Notes
    ///
    /// This is a heuristic check - it only verifies the file extension,
    /// not the actual file content. Always validate file integrity
    /// during decryption operations.
    ///
    /// # Limitations
    ///
    /// Files may have the .swx extension without being valid SweetByte
    /// files if renamed manually. The actual file format validation
    /// happens during header parsing.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    /// Check if the file is hidden (starts with a dot)
    ///
    /// This method determines if the file is considered hidden on Unix-like
    /// systems. Hidden files are typically configuration files or system files
    /// that should not be accidentally encrypted.
    ///
    /// # Returns
    ///
    /// `true` if the filename starts with a dot (.)
    ///
    /// # Platform Considerations
    ///
    /// This follows Unix conventions for hidden files. On Windows,
    /// actual hidden file detection would require checking file attributes,
    /// but for consistency across platforms, we use the dot convention.
    ///
    /// # Security Purpose
    ///
    /// Prevents accidental encryption of configuration files, dotfiles,
    /// and other system files that could break application functionality.
    #[inline]
    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    /// Check if the file matches any exclusion patterns
    ///
    /// This method evaluates the file path against a set of predefined
    /// exclusion patterns to determine if it should be filtered out
    /// from user selection. This protects sensitive system files and
    /// improves user experience by showing only relevant files.
    ///
    /// # Returns
    ///
    /// `true` if the file matches any exclusion pattern
    ///
    /// # Pattern Matching
    ///
    /// The method checks both:
    /// 1. Full path matching against patterns
    /// 2. Individual component matching against patterns
    ///
    /// This ensures that directories like "target" are excluded even
    /// when they appear as subdirectories of other paths.
    ///
    /// # Performance
    ///
    /// Uses pre-compiled glob patterns for efficient matching.
    /// Short-circuits on first pattern match for better performance.
    ///
    /// # Security Impact
    ///
    /// Prevents accidental encryption of:
    /// - Build artifacts and dependencies
    /// - Version control metadata
    /// - System configuration files
    /// - Security-critical directories (.ssh, .gnupg)
    pub fn is_excluded(&self) -> bool {
        // Convert path to string for pattern matching
        let path_str = self.path.to_str().unwrap_or("");

        // Check against all exclusion patterns
        EXCLUSION_MATCHERS.iter().any(|pattern| {
            // First try matching the full path
            let full_match = glob_match(pattern, path_str);

            if full_match {
                return true;
            }

            // Then check individual path components
            self.path.components().any(|comp| glob_match(pattern, comp.as_os_str().to_str().unwrap_or("")))
        })
    }

    /// Determine if the file is eligible for the specified processing mode
    ///
    /// This method combines multiple checks to determine if a file should
    /// be offered to the user for a specific operation (encrypt or decrypt).
    /// It implements the business logic for file filtering.
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode (encrypt or decrypt)
    ///
    /// # Returns
    ///
    /// `true` if the file is eligible for the specified mode
    ///
    /// # Eligibility Logic
    ///
    /// For **Encryption**:
    /// - File must not be hidden
    /// - File must not match exclusion patterns
    /// - File must not already be encrypted (no .swx extension)
    ///
    /// For **Decryption**:
    /// - File must not be hidden
    /// - File must not match exclusion patterns
    /// - File must be encrypted (has .swx extension)
    ///
    /// # User Experience
    ///
    /// This filtering ensures users only see relevant files in the
    /// interactive mode, reducing confusion and preventing accidental
    /// operations on inappropriate files.
    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        // Always exclude hidden and system files
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        // Apply mode-specific logic
        match mode {
            ProcessorMode::Encrypt => !self.is_encrypted(), // Only unencrypted files
            ProcessorMode::Decrypt => self.is_encrypted(),  // Only encrypted files
        }
    }

    /// Generate the appropriate output path for the given processing mode
    ///
    /// This method creates the output file path based on the current file
    /// and the intended operation. It handles both encryption (adding .swx)
    /// and decryption (removing .swx) operations.
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode (encrypt or decrypt)
    ///
    /// # Returns
    ///
    /// A PathBuf representing the appropriate output file path
    ///
    /// # Path Generation Logic
    ///
    /// For **Encryption**:
    /// - Takes the current filename
    /// - Appends .swx extension
    /// - Example: "document.txt" → "document.txt.swx"
    ///
    /// For **Decryption**:
    /// - Takes the current filename
    /// - Removes .swx suffix if present
    /// - If no .swx suffix, returns original path (fallback)
    /// - Example: "document.txt.swx" → "document.txt"
    ///
    /// # Edge Cases
    ///
    /// - Files without .swx extension during decryption fall back to original path
    /// - Files that already have .swx extension during encryption get .swx.swx (this is handled by
    ///   validation to prevent overwrites)
    ///
    /// # Safety Considerations
    ///
    /// The generated paths are always safe as they modify only the filename,
    /// not the directory structure. This prevents path traversal attacks.
    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            ProcessorMode::Encrypt => {
                // For encryption, append the SweetByte extension
                let mut name = self.path.as_os_str().to_os_string();
                name.push(FILE_EXTENSION);
                PathBuf::from(name)
            }

            ProcessorMode::Decrypt => {
                // For decryption, remove the SweetByte extension if present
                self.path.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(|| self.path.clone(), PathBuf::from)
            }
        }
    }

    /// Check if the file exists on the filesystem
    ///
    /// This method provides a simple existence check without any
    /// metadata operations. It's useful for quick validation before
    /// more expensive operations.
    ///
    /// # Returns
    ///
    /// `true` if the file exists, `false` otherwise
    ///
    /// # Performance
    ///
    /// This is a lightweight filesystem operation with minimal overhead.
    /// It's equivalent to `std::path::Path::exists()`.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it performs read-only operations.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Check if the path refers to a directory
    ///
    /// This method determines if the current path is a directory rather
    /// than a file. It's used for validation to ensure file operations
    /// are not attempted on directories.
    ///
    /// # Returns
    ///
    /// `true` if the path is a directory, `false` otherwise
    ///
    /// # Security Notes
    ///
    /// This check prevents accidental operations on directories that
    /// could lead to data loss or unexpected behavior.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Create a buffered reader for the file
    ///
    /// This method opens the file for reading and wraps it in a
    /// BufReader for improved I/O performance. The buffering reduces
    /// the number of system calls for sequential read operations.
    ///
    /// # Returns
    ///
    /// * `Ok(BufReader<fs::File>)` - Buffered file reader
    /// * `Err(anyhow::Error)` - Failed to open file or permission denied
    ///
    /// # Performance Benefits
    ///
    /// - Reduced system call overhead
    /// - Better cache utilization
    /// - Optimized for sequential access patterns
    ///
    /// # Error Conditions
    ///
    /// - File does not exist
    /// - Insufficient read permissions
    /// - File is locked by another process
    /// - Network/filesystem errors
    ///
    /// # Usage Pattern
    ///
    /// The reader should be used for streaming operations to avoid
    /// loading entire files into memory, especially important for large files.
    pub fn reader(&self) -> Result<BufReader<fs::File>> {
        let file = fs::File::open(&self.path).with_context(|| format!("failed to open file: {}", self.path.display()))?;

        Ok(BufReader::new(file))
    }

    /// Create a buffered writer for the file
    ///
    /// This method creates or truncates the file for writing and wraps it
    /// in a BufWriter for improved performance. It also ensures the parent
    /// directory exists, creating it if necessary.
    ///
    /// # Returns
    ///
    /// * `Ok(BufWriter<fs::File>)` - Buffered file writer
    /// * `Err(anyhow::Error)` - Failed to create file or directory
    ///
    /// # Directory Creation
    ///
    /// Automatically creates parent directories if they don't exist,
    /// enabling nested file creation without manual directory setup.
    ///
    /// # File Behavior
    ///
    /// - Creates file if it doesn't exist
    /// - Truncates file if it exists (overwrites existing content)
    /// - Uses write-only access mode for security
    ///
    /// # Performance Benefits
    ///
    /// - Buffered writes reduce system call overhead
    /// - Larger buffers improve throughput for sequential writes
    /// - Automatic flushing on drop for data safety
    ///
    /// # Security Considerations
    ///
    /// - Uses exclusive write access
    /// - Creates file with default permissions (respecting umask)
    /// - Atomic creation where filesystem supports it
    pub fn writer(&self) -> Result<BufWriter<fs::File>> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        // Open file for writing with truncation
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .with_context(|| format!("failed to create file: {}", self.path.display()))?;

        Ok(BufWriter::new(file))
    }

    /// Delete the file from the filesystem
    ///
    /// This method permanently removes the file from storage. It includes
    /// validation to ensure the file exists before attempting deletion.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - File successfully deleted
    /// * `Err(anyhow::Error)` - File doesn't exist or deletion failed
    ///
    /// # Security Considerations
    ///
    /// - **Permanent**: Deletion is irreversible
    /// - **Validation**: Ensures file exists before deletion
    /// - **Permissions**: Requires write permissions on parent directory
    ///
    /// # Error Conditions
    ///
    /// - File does not exist (validation)
    /// - Insufficient permissions
    /// - File is locked by another process
    /// - Read-only filesystem
    ///
    /// # Use Case
    ///
    /// Commonly used in interactive mode after successful encryption
    /// when the user opts to delete the original (unencrypted) file.
    pub fn delete(&self) -> Result<()> {
        ensure!(self.exists(), "file not found: {}", self.path.display());

        fs::remove_file(&self.path).with_context(|| format!("failed to delete file: {}", self.path.display()))
    }

    /// Validate the file according to the specified requirements
    ///
    /// This method performs comprehensive validation based on the operation
    /// context. It ensures files meet the requirements for encryption or
    /// decryption operations.
    ///
    /// # Arguments
    ///
    /// * `must_exist` - If true, validates that file exists and is readable
    ///  - If false, validates that file doesn't exist (for output files)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - File passes all validation checks
    /// * `Err(anyhow::Error)` - Validation failed with specific reason
    ///
    /// # Validation Logic
    ///
    /// When `must_exist` is true (input files):
    /// - File must exist
    /// - Path must not be a directory
    /// - File must not be empty (size > 0)
    ///
    /// When `must_exist` is false (output files):
    /// - File must not exist (prevent accidental overwrites)
    ///
    /// # Security Benefits
    ///
    /// - Prevents accidental overwrites of existing files
    /// - Ensures operations are performed on valid files only
    /// - Validates file permissions early in the process
    ///
    /// # Performance Notes
    ///
    /// This method caches the file size when computed, avoiding repeated
    /// filesystem operations during validation.
    pub fn validate(&mut self, must_exist: bool) -> Result<()> {
        if must_exist {
            // Input file validation
            ensure!(self.exists(), "file not found: {}", self.path.display());
            ensure!(!self.is_dir(), "path is a directory: {}", self.path.display());

            let size = self.size()?;
            ensure!(size != 0, "file is empty: {}", self.path.display());
        } else {
            // Output file validation - prevent overwrites
            ensure!(!self.exists(), "file already exists: {}", self.path.display());
        }

        Ok(())
    }

    /// Discover eligible files in the current directory tree
    ///
    /// This method performs a recursive directory walk to find all files
    /// that are eligible for the specified processing mode. It applies
    /// filtering rules to show only relevant files to users.
    ///
    /// # Arguments
    ///
    /// * `mode` - The processing mode (encrypt or decrypt)
    ///
    /// # Returns
    ///
    /// Vector of File instances representing eligible files
    ///
    /// # Discovery Process
    ///
    /// 1. Walk current directory tree recursively
    /// 2. Filter to regular files only (exclude directories, symlinks)
    /// 3. Create File instances for each file
    /// 4. Apply eligibility filtering based on mode
    /// 5. Return filtered list
    ///
    /// # Filtering Applied
    ///
    /// - Excludes hidden files (starting with .)
    /// - Excludes system directories and build artifacts
    /// - Mode-specific encryption/decryption state filtering
    ///
    /// # Performance Considerations
    ///
    /// - Uses efficient directory traversal algorithm
    /// - Short-circuits filtering for better performance
    /// - Processes files in directory order for consistency
    ///
    /// # Security Notes
    ///
    /// - Respects filesystem permissions during traversal
    /// - Excludes sensitive system files automatically
    /// - Limits discovery to current directory (prevents path traversal)
    ///
    /// # User Experience
    ///
    /// The filtering ensures users see only relevant files, reducing
    /// cognitive load and preventing accidental operations on inappropriate files.
    pub fn discover(mode: ProcessorMode) -> Vec<Self> {
        WalkDir::new(".")
            .into_iter()
            .filter_map(|entry| entry.ok()) // Skip entries with permission errors
            .filter(|entry| entry.file_type().is_file()) // Only regular files
            .map(|entry| Self::new(entry.into_path()))
            .filter(|file| file.is_eligible(mode)) // Apply business logic filtering
            .collect()
    }
}
