//! Cryptographic Hashing Module
//!
//! This module provides BLAKE3-based cryptographic hashing functionality for data integrity verification.
//! It implements constant-time comparison operations to prevent timing attacks and supports streaming
//! hash computation for large files with progress tracking.
//!
//! # Architecture
//! The Hash struct encapsulates a fixed-size BLAKE3 hash (256 bits) and provides methods for:
//! - Streaming hash computation from any Read source
//! - Constant-time verification against expected hash values
//! - Secure hash comparison using the subtle crate
//!
//! # Security Considerations
//! - Uses BLAKE3, a modern cryptographic hash function with proven security
//! - Implements constant-time comparison to prevent timing attacks
//! - Processes data in 256KB chunks for efficient memory usage
//! - Supports parallel hashing via Rayon for improved performance

use std::io::Read;

use anyhow::{Context, Result, ensure};
use blake3::Hasher;
use subtle::ConstantTimeEq;

use crate::config::HASH_SIZE;
use crate::ui::progress::ProgressBar;

/// Cryptographic hash container using BLAKE3 algorithm
///
/// This struct stores a 256-bit BLAKE3 hash and provides methods for secure
/// hash computation and verification. The hash is computed in a streaming
/// fashion to handle arbitrarily large data without loading everything into memory.
///
/// # Fields
/// - `hash`: Fixed-size array containing the 32-byte BLAKE3 hash digest
///
/// # Security
/// The hash comparison operations use constant-time equality checks to prevent
/// timing attacks that could leak information about hash values.
pub struct Hash {
    /// The 32-byte BLAKE3 hash digest
    hash: [u8; HASH_SIZE],
}

impl Hash {
    /// Computes BLAKE3 hash from a readable data source
    ///
    /// This method performs streaming hash computation using BLAKE3 algorithm.
    /// It processes data in 256KB chunks and uses Rayon for parallel processing
    /// to improve performance on multi-core systems.
    ///
    /// # Arguments
    /// * `reader` - Any type implementing the Read trait containing data to hash
    /// * `total_size` - Optional total size in bytes for progress tracking
    ///
    /// # Returns
    /// * `Result<Hash>` - The computed hash or an error if reading fails
    ///
    /// # Errors
    /// * I/O errors when reading from the data source
    /// * Progress bar initialization errors (if total_size is provided)
    ///
    /// # Performance
    /// - Uses 256KB buffer size for optimal I/O performance
    /// - Leverages Rayon for parallel BLAKE3 computation
    /// - O(n) time complexity where n is the total data size
    /// - Constant memory usage regardless of input size
    #[must_use]
    pub fn new<R: Read>(mut reader: R, total_size: Option<u64>) -> Result<Self> {
        // Initialize BLAKE3 hasher with default settings
        let mut hasher = Hasher::new();

        // Allocate 256KB buffer on heap for efficient I/O operations
        // This size balances memory usage with I/O throughput
        let mut buffer = Box::new([0u8; 256 * 1024]);

        // Initialize progress bar if total size is known for user feedback
        let progress = if let Some(size) = total_size { Some(ProgressBar::new(size, "Hashing...")?) } else { None };

        // Stream processing loop - read data in chunks until EOF
        loop {
            // Read up to buffer size from the data source
            let bytes_read = reader.read(&mut buffer[..]).context("failed to read data for hashing")?;

            // Check for end of file condition
            if bytes_read == 0 {
                break;
            }

            // Update hasher with the read data using Rayon for parallel processing
            // BLAKE3 is designed to take advantage of multiple cores
            hasher.update_rayon(&buffer[..bytes_read]);

            // Update progress bar if it's active
            if let Some(ref pb) = progress {
                pb.add(bytes_read as u64);
            }
        }

        // Clean up progress bar display
        if let Some(pb) = progress {
            pb.finish();
        }

        // Finalize the hash computation and extract the 32-byte digest
        let hash = *hasher.finalize().as_bytes();
        Ok(Self { hash })
    }

    /// Verifies this hash against an expected hash value
    ///
    /// Performs constant-time comparison to prevent timing attacks that could
    /// leak information about the hash values during verification.
    ///
    /// # Arguments
    /// * `expected` - The expected hash value to verify against (32-byte array)
    ///
    /// # Returns
    /// * `Result<()>` - Success if hashes match, error if they don't
    ///
    /// # Errors
    /// * Returns error if hash verification fails, indicating data corruption or tampering
    ///
    /// # Security
    /// Uses subtle::ConstantTimeEq to prevent timing attacks during comparison.
    /// This ensures that the comparison takes the same amount of time regardless of
    /// where (or if) the differences occur in the hash values.
    pub fn verify(&self, expected: &[u8; HASH_SIZE]) -> Result<()> {
        // Perform constant-time equality check to prevent timing attacks
        // The ct_eq method returns a Choice type that must be converted to bool
        ensure!(bool::from(self.hash.ct_eq(expected)), "content hash verification failed: data integrity compromised");
        Ok(())
    }

    /// Returns a reference to the raw hash bytes
    ///
    /// Provides direct access to the 32-byte hash digest for serialization
    /// or other operations that need the raw bytes.
    ///
    /// # Returns
    /// * `&[u8; HASH_SIZE]` - Immutable reference to the 32-byte hash array
    ///
    /// # Security Note
    /// The returned reference allows read-only access to maintain hash integrity.
    /// Modifications to the hash should only occur through the constructor.
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_new() {
        let data = b"test data";
        let hash = Hash::new(&data[..], None).unwrap();
        assert_eq!(hash.as_bytes().len(), HASH_SIZE);
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"same data";
        let hash1 = Hash::new(&data[..], None).unwrap();
        let hash2 = Hash::new(&data[..], None).unwrap();
        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }

    #[test]
    fn test_hash_verify_valid() {
        let data = b"verify me";
        let hash = Hash::new(&data[..], None).unwrap();
        assert!(hash.verify(hash.as_bytes()).is_ok());
    }

    #[test]
    fn test_hash_verify_invalid() {
        let data = b"verify me";
        let hash = Hash::new(&data[..], None).unwrap();
        let mut corrupted = *hash.as_bytes();
        corrupted[0] ^= 0x01;
        assert!(hash.verify(&corrupted).is_err());
    }

    #[test]
    fn test_hash_empty() {
        let hash = Hash::new(&[][..], None).unwrap();
        assert!(hash.verify(hash.as_bytes()).is_ok());
    }
}
