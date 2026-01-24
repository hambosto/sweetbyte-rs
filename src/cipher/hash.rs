//! # BLAKE3 Hashing Module
//!
//! This module provides BLAKE3 hashing functionality for data integrity verification.
//! BLAKE3 is a modern, fast, and secure cryptographic hash function that offers
//! excellent performance on modern CPUs with parallelization capabilities.
//!
//! ## Security Properties
//!
//! - **Collision Resistance**: 256-bit output provides 2^128 collision resistance
//! - **Preimage Resistance**: 256-bit output provides 2^256 preimage resistance
//! - **Parallelization**: Designed for efficient parallel computation
//! - **Performance**: Fastest modern hash function on most hardware
//!
//! ## Features
//!
/// - **Rayon Integration**: Uses Rayon for parallel processing of large data
/// - **Constant-Time Verification**: Prevents timing attacks during hash comparison
/// - **Memory Efficiency**: Streaming hash computation for large files
/// - **XOF Support**: Can be extended for arbitrary-length output if needed
use anyhow::{Result, ensure};
use subtle::ConstantTimeEq;

use crate::config::HASH_SIZE;

/// # BLAKE3 Hash Wrapper
///
/// Provides convenient BLAKE3 hashing with parallel processing support
/// and constant-time verification for security-sensitive comparisons.
///
/// The hash output is 32 bytes (256 bits) providing strong security guarantees
/// while maintaining excellent performance characteristics.
///
/// ## Security Considerations
///
/// - Uses constant-time comparison to prevent timing attacks
/// - Parallel processing improves performance without compromising security
/// - BLAKE3 is designed for modern hardware and is widely trusted
/// - Suitable for both integrity verification and deduplication
pub struct Hash {
    /// The 256-bit BLAKE3 hash digest
    /// Stored as a fixed-size array for efficient memory layout
    hash: [u8; HASH_SIZE],
}

impl Hash {
    /// Computes BLAKE3 hash of input data with parallel processing
    ///
    /// Creates a BLAKE3 hash of the provided data using Rayon for parallel
    /// processing when beneficial (typically for data larger than a few KB).
    ///
    /// # Arguments
    /// * `data` - Input data to hash, can be any size including empty
    ///
    /// # Returns
    /// Hash instance containing the 256-bit BLAKE3 digest
    ///
    /// # Security Guarantees
    /// - Cryptographically secure hash function
    /// - Collision resistant with 2^128 security level
    /// - Preimage resistant with 2^256 security level
    /// - Deterministic: same input always produces same output
    ///
    /// # Performance Characteristics
    /// - O(n) complexity where n is input length
    /// - Parallel processing for large inputs (> few KB)
    /// - Hardware-accelerated on supported CPUs (SIMD instructions)
    /// - Memory-efficient streaming computation
    ///
    /// # Notes
    /// - Uses Rayon thread pool for parallel processing
    /// - Empty input produces a valid, non-zero hash
    /// - Suitable for files of any size, including gigabytes
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        // Create new BLAKE3 hasher instance
        let mut hasher = blake3::Hasher::new();

        // Update hasher with input data using parallel processing
        // update_rayon automatically uses parallelism when beneficial
        // For small inputs, it behaves like regular update()
        hasher.update_rayon(data);

        // Finalize hash computation and extract 32-byte digest
        // finalize() returns a Hash type, as_bytes() provides &[u8; 32]
        let hash = *hasher.finalize().as_bytes();
        Self { hash }
    }

    /// Returns the hash digest as a byte array reference
    ///
    /// Provides access to the underlying 256-bit hash digest for storage,
    /// comparison, or serialization purposes.
    ///
    /// # Returns
    /// Reference to the 32-byte BLAKE3 hash digest
    ///
    /// # Security Notes
    /// - Returns an immutable reference, hash cannot be modified
    /// - The hash value itself is not secret
    /// - Suitable for storage alongside encrypted data
    ///
    /// # Performance
    /// - Zero-cost operation: just returns a reference
    /// - No copying or allocation involved
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }

    /// Verifies that the hash matches an expected value
    ///
    /// Performs constant-time comparison to prevent timing attacks that could
    /// leak information about the hash value or input data.
    ///
    /// # Arguments
    /// * `expected` - Expected hash value to compare against (32 bytes)
    ///
    /// # Returns
    /// Ok(()) if hashes match, Err() if they differ
    ///
    /// # Errors
    /// Returns error if:
    /// - Hashes do not match (indicates data corruption or tampering)
    ///
    /// # Security Guarantees
    /// - Constant-time comparison prevents timing attacks
    /// - No early return on mismatched bytes
    /// - Attackers cannot gain information about hash values through timing
    /// - Provides cryptographic integrity verification
    ///
    /// # Performance
    /// - O(1) time complexity (constant 32-byte comparison)
    /// - No early exit: always compares all 32 bytes
    /// - Minimal overhead over direct byte comparison
    ///
    /// # Use Cases
    /// - File integrity verification after decryption
    /// - Detecting data corruption during transmission
    /// - Verifying that decrypted data matches original hash
    pub fn verify(&self, expected: &[u8; HASH_SIZE]) -> Result<()> {
        // Perform constant-time equality check using subtle crate
        // ct_eq() returns a Choice type that prevents early exit
        // This prevents timing attacks that could leak hash information
        ensure!(bool::from(self.hash.ct_eq(expected)), "content hash verification failed: data integrity compromised");
        Ok(())
    }
}
