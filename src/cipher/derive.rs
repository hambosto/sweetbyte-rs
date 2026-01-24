//! # Key Derivation with Argon2id
//!
//! This module provides secure key derivation using Argon2id, a memory-hard
//! password hashing algorithm designed to resist GPU and ASIC attacks.
//! Argon2id combines Argon2i (resistant to side-channel attacks) and
//! Argon2d (resistant to GPU cracking attacks) for optimal security.
//!
//! ## Security Properties
//!
//! - **Memory-Hard**: Requires significant memory to compute, preventing GPU/ASIC acceleration
//! - **Time-Hard**: Configurable iteration count for increased work factor
//! - **Parallelism**: Configurable thread count for adaptive resistance
//! - **Side-Channel Resistance**: Argon2id component protects against timing attacks
//!
//! ## Parameter Selection
//!
//! - **Memory**: Amount of memory in KiB (recommended: 64MB+ for interactive use)
//! - **Time**: Number of iterations (recommended: 3+ for interactive use)
//! - **Parallelism**: Number of threads (recommended: number of CPU cores)
//! - **Output Length**: 64 bytes (512 bits) for dual encryption keys
//!
//! ## Threat Model
//!
/// Protects against: GPU/ASIC cracking, rainbow table attacks, side-channel attacks
use anyhow::{Result, anyhow, ensure};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::ARGON_KEY_LEN;

/// # Key Derivation Function
///
/// Wrapper for Argon2id key derivation with secure salt generation.
/// Derives cryptographic keys from passwords or low-entropy inputs
/// using memory-hard computation to resist brute-force attacks.
///
/// The derived key is split between AES-256-GCM and XChaCha20-Poly1305
/// for defense-in-depth encryption strategy.
///
/// ## Security Considerations
///
/// - Uses Argon2id (v1.3) for optimal security against all attack vectors
/// - Derives 64-byte key: 32 bytes for AES, 32 bytes for ChaCha20
/// - Salt generation uses OS cryptographically secure randomness
/// - Parameters should be tuned based on available hardware and security requirements
pub struct Derive {
    /// The original password/key material to be used for derivation
    /// Stored as `Vec<u8>` to support variable-length inputs
    key: Vec<u8>,
}

impl Derive {
    /// Creates a new key derivation instance
    ///
    /// # Arguments
    /// * `key` - Password or key material to derive from, must not be empty
    ///
    /// # Returns
    /// Configured Derive instance ready for key derivation operations
    ///
    /// # Errors
    /// Returns error if the input key is empty
    ///
    /// # Security Notes
    /// - The key material is copied into the struct for repeated derivation
    /// - Consider using a secure allocator for sensitive material in production
    /// - The key should be zeroized when the Derive instance is dropped
    pub fn new(key: &[u8]) -> Result<Self> {
        // Validate input to prevent empty password derivation
        ensure!(!key.is_empty(), "key cannot be empty");
        Ok(Self { key: key.to_vec() })
    }

    /// Derives a cryptographic key using Argon2id
    ///
    /// Performs memory-hard key derivation with configurable parameters.
    /// The output is suitable for use as encryption keys for the cipher modules.
    ///
    /// # Arguments
    /// * `salt` - Salt for key derivation, should be unique per password/user
    /// * `memory` - Memory cost in KiB (e.g., 65536 = 64MB)
    /// * `time` - Number of iterations (time cost)
    /// * `parallelism` - Number of threads to use (parallelism cost)
    ///
    /// # Returns
    /// 64-byte derived key suitable for splitting between AES and ChaCha20
    ///
    /// # Errors
    /// Returns error if:
    /// - Argon2 parameters are invalid (out of range)
    /// - Key derivation operation fails
    /// - Memory allocation fails
    ///
    /// # Security Guarantees
    /// - Memory-hard computation resists GPU/ASIC attacks
    /// - Salt prevents rainbow table attacks
    /// - Argon2id provides side-channel resistance
    /// - Output is cryptographically strong and uniformly distributed
    ///
    /// # Parameter Recommendations
    /// - Interactive (online): memory=64MB+, time=3+, parallelism=cores
    /// - Sensitive (offline): memory=1GB+, time=5+, parallelism=cores
    /// - Resource-constrained: adjust proportionally while maintaining security
    ///
    /// # Performance Characteristics
    /// - O(memory × time × parallelism) computation time
    /// - Memory usage scales linearly with memory parameter
    /// - Parallel execution possible based on parallelism parameter
    pub fn derive_key(&self, salt: &[u8], memory: u32, time: u32, parallelism: u32) -> Result<[u8; ARGON_KEY_LEN]> {
        // Validate and create Argon2id parameters
        // The function ensures parameters are within acceptable ranges
        let params = Params::new(memory, time, parallelism, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameter: {e}"))?;
        // Create Argon2id instance with v1.3 parameters
        // Argon2id provides optimal security against both GPU and side-channel attacks
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        // Derive key into pre-allocated output buffer
        // The output buffer is zero-initialized and overwritten with the derived key
        let mut key = [0u8; ARGON_KEY_LEN];
        argon2.hash_password_into(&self.key, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {e}"))?;

        Ok(key)
    }

    /// Generates a cryptographically secure random salt
    ///
    /// Creates a random salt suitable for use with Argon2id key derivation.
    /// Uses the operating system's cryptographically secure random number generator.
    ///
    /// # Type Parameters
    /// * `N` - Length of salt to generate (typically 16-32 bytes)
    ///
    /// # Returns
    /// Cryptographically secure random salt of specified length
    ///
    /// # Errors
    /// Returns error if the operating system's random number generator fails
    ///
    /// # Security Notes
    /// - Uses OS-provided cryptographically secure randomness
    /// - Salt length should be at least 16 bytes for collision resistance
    /// - Each password should use a unique salt to prevent precomputation attacks
    /// - Salts are not secret and can be stored alongside the encrypted data
    ///
    /// # Recommended Salt Lengths
    /// - 16 bytes: Minimum recommended length
    /// - 24 bytes: Good security margin
    /// - 32 bytes: Maximum practical security benefit
    ///
    /// # Performance
    /// - O(N) time complexity where N is the salt length
    /// - Typically negligible compared to key derivation cost
    /// - Uses OS-optimized random number generation
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        // Initialize buffer with zeros (not strictly necessary but good practice)
        let mut bytes = [0u8; N];
        // Fill buffer with cryptographically secure random bytes
        // OsRng provides platform-specific secure randomness (e.g., /dev/urandom, CryptGenRandom)
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {e}"))?;

        Ok(bytes)
    }
}
