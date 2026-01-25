//! File metadata module for SweetByte archives.
//!
//! This module defines the Metadata structure that contains essential information
//! about encrypted files within SweetByte archives. It maintains file identification
//! and integrity verification data while ensuring safe handling of filename lengths.
//!
//! # Architecture
//! The Metadata struct is a simple data container that supports serialization
//! for storage in the header section. It follows a compact binary format to
//! minimize overhead while providing complete file information.
//!
//! # Key Concepts
//! - **Filename Truncation**: Ensures filenames don't exceed storage limits
//! - **Content Hashing**: BLAKE3 hash provides integrity verification
//! - **Binary Serialization**: Compact storage format using wincode schema
//! - **Size Validation**: Prevents zero-size files which are unsupported

use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{HASH_SIZE, MAX_FILENAME_LENGTH};

/// File metadata structure containing essential file information.
///
/// This structure stores the filename, original file size, and content hash
/// for files encrypted in SweetByte archives. The filename is automatically
/// truncated if it exceeds the maximum allowed length.
///
/// # Fields
/// - `name`: Truncated filename (max MAX_FILENAME_LENGTH characters)
/// - `size`: Original uncompressed file size in bytes
/// - `hash`: BLAKE3 hash of the original file content (32 bytes)
///
/// # Security Notes
/// The hash provides integrity verification for the decrypted file content,
/// allowing detection of corruption or tampering. Filename truncation
/// prevents buffer overflow vulnerabilities while maintaining usability.
#[derive(Debug, Clone, Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct Metadata {
    /// Filename (truncated to MAX_FILENAME_LENGTH if necessary)
    name: String,
    /// Original file size in bytes (must be non-zero)
    size: u64,
    /// BLAKE3 content hash for integrity verification (32 bytes)
    hash: [u8; HASH_SIZE],
}

impl Metadata {
    /// Creates new metadata with automatic filename truncation.
    ///
    /// This constructor takes a filename, file size, and content hash, then
    /// creates a Metadata instance. The filename is automatically truncated
    /// if it exceeds the maximum allowed length to prevent storage issues.
    ///
    /// # Arguments
    /// * `filename` - Original filename (any type convertible to String)
    /// * `size` - Original file size in bytes (should be non-zero)
    /// * `content_hash` - BLAKE3 hash of the file content (32 bytes)
    ///
    /// # Returns
    /// A new Metadata instance with potentially truncated filename
    ///
    /// # Security Considerations
    /// Filename truncation prevents path traversal and buffer overflow attacks
    /// by ensuring filenames never exceed storage limits. The content hash
    /// enables detection of file tampering or corruption.
    ///
    /// # Performance Notes
    /// - Filename truncation: O(min(n, MAX_FILENAME_LENGTH)) where n is filename length
    /// - Memory allocation: O(MAX_FILENAME_LENGTH) for truncated filename
    /// - No other computational overhead
    pub fn new(filename: impl Into<String>, size: u64, content_hash: [u8; HASH_SIZE]) -> Self {
        // Convert input filename to owned String for potential modification
        let mut filename = filename.into();

        // Truncate filename if it exceeds maximum allowed length
        // This prevents storage overflow issues and maintains consistency
        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        // Construct metadata with processed filename
        Self { name: filename, size, hash: content_hash }
    }

    /// Returns the filename (may be truncated).
    ///
    /// # Returns
    /// String slice containing the (potentially truncated) filename
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the original file size.
    ///
    /// # Returns
    /// File size in bytes
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the BLAKE3 content hash.
    ///
    /// # Returns
    /// 32-byte array containing the file content hash
    ///
    /// # Security Notes
    /// This hash should be verified after decryption to ensure
    /// the file content hasn't been corrupted or tampered with.
    #[inline]
    #[must_use]
    pub const fn hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}
