//! File Metadata Management
//!
//! This module handles the serialization and deserialization of file metadata within
//! the encrypted file header. The metadata structure contains essential file
//! information that must be accessible without decrypting the entire file:
//!
//! - **Filename** - Original file name (truncated if exceeds maximum length)
//! - **File Size** - Original uncompressed file size in bytes
//! - **Content Hash** - SHA-256 hash of the original file content
//!
//! ## Binary Serialization Format
//!
//! The metadata is stored in a compact binary format optimized for size:
//!
//! ```text
//! [2 bytes] Filename length (big-endian u16)
//! [N bytes] UTF-8 filename data (N = filename length)
//! [8 bytes] File size (big-endian u64)
//! [32 bytes] Content hash (SHA-256)
//! ```
//!
//! ## Security Considerations
//!
//! - The filename length field prevents buffer overflow attacks
//! - Maximum filename length is enforced to prevent DoS via overly long names
//! - The content hash enables integrity verification without full decryption
//! - All numeric fields use big-endian format for consistent cross-platform behavior
//!
//! ## Performance Characteristics
//!
//! - Serialization is O(n) where n is the filename length
//! - Deserialization validates all fields and bounds
//! - Memory allocation is minimized by pre-calculating required buffer sizes

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::config::{HASH_SIZE, MAX_FILENAME_LENGTH};

/// File metadata container
///
/// This structure stores essential file information that is preserved through
/// the encryption process. The metadata is stored in the encrypted header
/// and can be accessed without decrypting the entire file.
///
/// The filename is automatically truncated if it exceeds the configured maximum
/// length to ensure consistent header sizes and prevent potential DoS attacks.
#[derive(Debug, Clone, Serialize)]
pub struct FileMetadata {
    /// Original filename (may be truncated to MAX_FILENAME_LENGTH)
    name: String,
    /// Original file size in bytes (uncompressed)
    size: u64,
    /// SHA-256 hash of the original file content for integrity verification
    hash: [u8; HASH_SIZE],
}

impl FileMetadata {
    // Constants for the binary serialization format
    const FILENAME_LEN_SIZE: usize = 2; // 2 bytes for filename length (u16)
    const SIZE_FIELD_SIZE: usize = 8; // 8 bytes for file size (u64)
    const MIN_SERIALIZED_SIZE: usize = Self::FILENAME_LEN_SIZE + Self::SIZE_FIELD_SIZE + HASH_SIZE;

    /// Create new file metadata
    ///
    /// This constructor creates a new FileMetadata instance, automatically handling
    /// filename truncation if necessary to maintain consistent header sizes.
    ///
    /// # Arguments
    ///
    /// * `filename` - The original filename (will be truncated if too long)
    /// * `size` - The uncompressed file size in bytes
    /// * `content_hash` - SHA-256 hash of the original file content
    ///
    /// # Returns
    ///
    /// A new FileMetadata instance with potentially truncated filename.
    ///
    /// # Security Notes
    ///
    /// - Automatic filename truncation prevents DoS via overly long names
    /// - The truncation is performed before any serialization to ensure consistent sizes
    pub fn new(filename: impl Into<String>, size: u64, content_hash: [u8; HASH_SIZE]) -> Self {
        let mut filename = filename.into();

        // Enforce maximum filename length for security and consistency
        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        Self { name: filename, size, hash: content_hash }
    }

    /// Get the filename
    ///
    /// # Returns
    ///
    /// Reference to the (potentially truncated) filename string.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the file size
    ///
    /// # Returns
    ///
    /// The original uncompressed file size in bytes.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Get the content hash
    ///
    /// # Returns
    ///
    /// Reference to the SHA-256 hash of the original file content.
    #[inline]
    #[must_use]
    pub const fn hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }

    /// Serialize metadata to binary format
    ///
    /// Converts the metadata into the compact binary format suitable for storage
    /// in the encrypted header. The format is:
    ///
    /// ```text
    /// [2 bytes] filename length (big-endian u16)
    /// [N bytes] UTF-8 filename data
    /// [8 bytes] file size (big-endian u64)  
    /// [32 bytes] SHA-256 hash
    /// ```
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the serialized metadata.
    ///
    /// # Performance Notes
    ///
    /// - Pre-calculates the required buffer size to avoid reallocations
    /// - Uses big-endian format for consistent cross-platform behavior
    /// - All numeric fields are fixed-size for predictable serialization
    pub fn serialize(&self) -> Vec<u8> {
        let filename_bytes = self.name.as_bytes();
        let filename_len = filename_bytes.len() as u16;

        // Pre-calculate total size to avoid reallocations during building
        let total_size = Self::FILENAME_LEN_SIZE + filename_bytes.len() + Self::SIZE_FIELD_SIZE + HASH_SIZE;
        let mut data = Vec::with_capacity(total_size);

        // Build the binary format in order
        data.extend_from_slice(&filename_len.to_be_bytes()); // Filename length
        data.extend_from_slice(filename_bytes); // Filename data
        data.extend_from_slice(&self.size.to_be_bytes()); // File size
        data.extend_from_slice(&self.hash); // Content hash

        data
    }

    /// Deserialize metadata from binary format
    ///
    /// Parses binary data into a FileMetadata instance, performing comprehensive
    /// validation of all fields and bounds checking for security.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data containing serialized metadata
    ///
    /// # Returns
    ///
    /// A Result containing either the parsed FileMetadata or an error.
    ///
    /// # Errors
    ///
    /// - Invalid binary format (too short data)
    /// - Filename length exceeds maximum allowed
    /// - Invalid UTF-8 in filename data
    /// - Type conversion failures for numeric fields
    ///
    /// # Security Validation
    ///
    /// - Validates minimum data length before any parsing
    /// - Enforces maximum filename length to prevent DoS
    /// - Validates actual data length matches expected based on filename length
    /// - All numeric conversions are bounds-checked
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        // Step 1: Basic length validation - ensure we have at least the minimum required bytes
        ensure!(data.len() >= Self::MIN_SERIALIZED_SIZE, "metadata too short: expected at least {} bytes, got {}", Self::MIN_SERIALIZED_SIZE, data.len());

        // Step 2: Extract and validate filename length
        let filename_len = Self::read_filename_length(data)?;
        ensure!(filename_len <= MAX_FILENAME_LENGTH, "filename too long: {filename_len} bytes (max {MAX_FILENAME_LENGTH})");

        // Step 3: Calculate and validate total required length based on filename length
        let required_len = Self::calculate_required_length(filename_len);
        ensure!(data.len() >= required_len, "metadata too short: expected {}, got {}", required_len, data.len());

        // Step 4: Extract all fields in order with proper validation
        let filename = Self::read_filename(data, filename_len)?;
        let size = Self::read_size(data, filename_len)?;
        let content_hash = Self::read_content_hash(data, filename_len)?;

        Ok(Self { name: filename, size, hash: content_hash })
    }

    /// Read the filename length field from binary data
    ///
    /// Extracts the 2-byte filename length field and converts it from big-endian.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data with at least 2 bytes available
    ///
    /// # Returns
    ///
    /// Result containing the filename length as usize.
    ///
    /// # Errors
    ///
    /// Type conversion failure if the byte slice cannot be converted to [u8; 2].
    fn read_filename_length(data: &[u8]) -> Result<usize> {
        let bytes = data[0..Self::FILENAME_LEN_SIZE].try_into().context("filename length conversion")?;
        Ok(u16::from_be_bytes(bytes) as usize)
    }

    /// Calculate the total required length for a given filename length
    ///
    /// Helper function to compute the expected total size of the serialized metadata.
    ///
    /// # Arguments
    ///
    /// * `filename_len` - Length of the filename in bytes
    ///
    /// # Returns
    ///
    /// The total required length in bytes.
    fn calculate_required_length(filename_len: usize) -> usize {
        Self::FILENAME_LEN_SIZE + filename_len + Self::SIZE_FIELD_SIZE + HASH_SIZE
    }

    /// Read and validate the filename field
    ///
    /// Extracts the UTF-8 filename data from the binary format and validates
    /// that it contains valid UTF-8 sequences.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data containing the metadata
    /// * `filename_len` - Length of the filename field (already validated)
    ///
    /// # Returns
    ///
    /// Result containing the filename as a String.
    ///
    /// # Errors
    ///
    /// Invalid UTF-8 sequences in the filename data.
    fn read_filename(data: &[u8], filename_len: usize) -> Result<String> {
        let start = Self::FILENAME_LEN_SIZE;
        let end = start + filename_len;

        std::str::from_utf8(&data[start..end]).context("invalid UTF-8 in filename").map(|s| s.to_owned())
    }

    /// Read the file size field
    ///
    /// Extracts the 8-byte file size field and converts it from big-endian.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data containing the metadata
    /// * `filename_len` - Length of the filename field (for offset calculation)
    ///
    /// # Returns
    ///
    /// Result containing the file size as u64.
    ///
    /// # Errors
    ///
    /// Type conversion failure if the byte slice cannot be converted to [u8; 8].
    fn read_size(data: &[u8], filename_len: usize) -> Result<u64> {
        let start = Self::FILENAME_LEN_SIZE + filename_len;
        let end = start + Self::SIZE_FIELD_SIZE;

        let bytes = data[start..end].try_into().context("size conversion")?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Read the content hash field
    ///
    /// Extracts the 32-byte content hash field (SHA-256).
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data containing the metadata
    /// * `filename_len` - Length of the filename field (for offset calculation)
    ///
    /// # Returns
    ///
    /// Result containing the content hash as [u8; HASH_SIZE].
    ///
    /// # Errors
    ///
    /// Type conversion failure if the byte slice cannot be converted to the expected array size.
    fn read_content_hash(data: &[u8], filename_len: usize) -> Result<[u8; HASH_SIZE]> {
        let start = Self::FILENAME_LEN_SIZE + filename_len + Self::SIZE_FIELD_SIZE;
        let end = start + HASH_SIZE;

        data[start..end].try_into().context("content hash conversion")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_new_truncation() {
        let long_name = "a".repeat(MAX_FILENAME_LENGTH + 10);
        let hash = [0u8; HASH_SIZE];
        let metadata = FileMetadata::new(long_name, 100, hash);

        assert_eq!(metadata.name.len(), MAX_FILENAME_LENGTH);
    }

    #[test]
    fn test_metadata_roundtrip() {
        let name = "test.txt";
        let size = 12345;
        let hash = [1u8; HASH_SIZE];
        let metadata = FileMetadata::new(name, size, hash);

        let serialized = metadata.serialize();
        let deserialized = FileMetadata::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.name, name);
        assert_eq!(deserialized.size, size);
        assert_eq!(deserialized.hash, hash);
    }

    #[test]
    fn test_metadata_deserialize_too_short() {
        let data = vec![0u8; 10];
        assert!(FileMetadata::deserialize(&data).is_err());
    }

    #[test]
    fn test_metadata_deserialize_invalid_utf8() {
        let name = "test";
        let size = 100;
        let hash = [0u8; HASH_SIZE];
        let mut serialized = FileMetadata::new(name, size, hash).serialize();

        let name_start = 2;
        serialized[name_start] = 0xFF;
        serialized[name_start + 1] = 0xFF;

        assert!(FileMetadata::deserialize(&serialized).is_err());
    }
}
