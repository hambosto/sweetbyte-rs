//! Content integrity verification using BLAKE3.
//!
//! This module handles the computation and verification of cryptographic hashes
//! to ensure file integrity. We use **BLAKE3**, which is:
//! - Extremely fast (much faster than MD5, SHA-1, SHA-2, SHA-3)
//! - Secure (based on the Bao tree hash mode and ChaCha stream cipher)
//! - Parallelizable (utilized here via Rayon integration)
//!
//! # Architecture
//!
//! The [`struct@Hash`] struct processes data streams asynchronously, allowing for efficient
//! overlapping of I/O (reading from disk) and CPU work (hashing).

use anyhow::{Context, Result, ensure};
use blake3::Hasher;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::HASH_SIZE;
use crate::ui::progress::ProgressBar;

/// A container for a computed BLAKE3 hash.
///
/// This struct holds the final 32-byte hash digest and provides methods
/// for verification and serialization.
pub struct Hash {
    /// The 32-byte BLAKE3 hash digest.
    hash: [u8; HASH_SIZE],
}

impl Hash {
    /// Computes the hash of a data stream asynchronously.
    ///
    /// This method reads from the provided async reader until EOF, updates
    /// the hasher, and optionally updates a progress bar.
    ///
    /// # Arguments
    ///
    /// * `reader` - The async source of data (e.g., file, socket).
    /// * `total_size` - Optional total size in bytes for the progress bar.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the underlying stream fails.
    pub async fn new<R: AsyncRead + Unpin>(mut reader: R, total_size: Option<u64>) -> Result<Self> {
        // Initialize the BLAKE3 hasher.
        let mut hasher = Hasher::new();

        // allocate a large buffer (256 KiB) on the heap to minimize system calls.
        // We use Box to avoid blowing up the stack.
        let mut buffer = Box::new([0u8; 256 * 1024]);

        // Initialize progress bar if total size is known.
        // This gives user feedback during long hashing operations.
        let progress = if let Some(size) = total_size { Some(ProgressBar::new(size, "Hashing...")?) } else { None };

        // Read loop: consume stream until EOF.
        loop {
            // Read a chunk of data into the buffer.
            let bytes_read = reader.read(&mut buffer[..]).await.context("failed to read data for hashing")?;

            // EOF check.
            if bytes_read == 0 {
                break;
            }

            // Update the hasher with the read chunk.
            // update_rayon leverages multithreading for large inputs if the chunk is huge,
            // though here we are feeding 256KB chunks which might be single-threaded depending on BLAKE3
            // config. (Standard update() is extremely fast anyway).
            hasher.update_rayon(&buffer[..bytes_read]);

            // Update progress bar.
            if let Some(ref pb) = progress {
                pb.add(bytes_read as u64);
            }
        }

        // Complete the progress bar.
        if let Some(pb) = progress {
            pb.finish();
        }

        // Finalize the hash computation.
        // This produces the 32-byte digest.
        let hash = *hasher.finalize().as_bytes();

        Ok(Self { hash })
    }

    /// Verifies that the stored hash matches an expected hash.
    ///
    /// This comparison is performed in constant time to prevent timing attacks,
    /// although for public hashes this is less critical than for MACs.
    ///
    /// # Errors
    ///
    /// Returns an error if the hashes do not match.
    #[inline]
    pub fn verify(&self, expected: &[u8; HASH_SIZE]) -> Result<()> {
        // Use constant-time equality check.
        // Even though this is a hash and not a MAC, treating it as sensitive
        // prevents any potential timing leaks if the hash is used in a sensitive context.
        ensure!(bool::from(self.hash.ct_eq(expected)), "content hash verification failed: data integrity compromised");
        Ok(())
    }

    /// Returns a reference to the raw hash bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hash_new() {
        let data = b"test data";
        let hash = Hash::new(&data[..], None).await.unwrap();
        assert_eq!(hash.as_bytes().len(), HASH_SIZE);
    }

    #[tokio::test]
    async fn test_hash_deterministic() {
        let data = b"same data";
        let hash1 = Hash::new(&data[..], None).await.unwrap();
        let hash2 = Hash::new(&data[..], None).await.unwrap();
        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }

    #[tokio::test]
    async fn test_hash_verify_valid() {
        let data = b"verify me";
        let hash = Hash::new(&data[..], None).await.unwrap();
        assert!(hash.verify(hash.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn test_hash_verify_invalid() {
        let data = b"verify me";
        let hash = Hash::new(&data[..], None).await.unwrap();
        let mut corrupted = *hash.as_bytes();
        corrupted[0] ^= 0x01; // Flip a bit
        assert!(hash.verify(&corrupted).is_err());
    }

    #[tokio::test]
    async fn test_hash_empty() {
        // Hashing empty data is valid and produces a specific hash.
        let hash = Hash::new(&[][..], None).await.unwrap();
        assert!(hash.verify(hash.as_bytes()).is_ok());
    }
}
