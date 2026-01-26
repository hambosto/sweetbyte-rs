//! File metadata definitions.
//!
//! This module defines the `Metadata` struct, which stores essential information
//! about the encrypted file, including its original name, size, and integrity hash.
//! This metadata is encrypted and stored within the file header.

use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{HASH_SIZE, MAX_FILENAME_LENGTH};

/// Container for file metadata.
///
/// This struct is serialized and stored in the encrypted header.
#[derive(Debug, Clone, Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct Metadata {
    /// The original filename (truncated if necessary).
    name: String,

    /// The size of the original unencrypted file in bytes.
    size: u64,

    /// The BLAKE3 hash of the original plaintext content.
    /// Used to verify data integrity after decryption.
    hash: [u8; HASH_SIZE],
}

impl Metadata {
    /// Creates a new metadata instance.
    ///
    /// The filename is automatically truncated to [`MAX_FILENAME_LENGTH`] to ensure
    /// the header remains within reasonable size limits.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file being encrypted.
    /// * `size` - Size in bytes.
    /// * `content_hash` - BLAKE3 hash of the content.
    pub fn new(filename: impl Into<String>, size: u64, content_hash: [u8; HASH_SIZE]) -> Self {
        let mut filename = filename.into();

        // Enforce maximum filename length constraint.
        // This prevents header bloat and potential denial-of-service vectors.
        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        Self { name: filename, size, hash: content_hash }
    }

    /// Returns the stored filename.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the original file size.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the content hash.
    #[inline]
    #[must_use]
    pub const fn hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}
