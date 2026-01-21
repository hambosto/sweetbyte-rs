//! Argon2id key derivation and salt generation.
//!
//! Provides password hardening using Argon2id, the winner of the
//! Password Hashing Competition. This module also handles secure
//! random salt generation.
//!
//! # Security Parameters
//!
//! - **Algorithm**: Argon2id (hybrid of Argon2d and Argon2i)
//! - **Memory**: 64 MB (64 * 1024 bytes)
//! - **Iterations**: 3
//! - **Parallelism**: 4 threads
//! - **Output length**: 64 bytes
//!
//! These parameters are chosen to resist GPU/ASIC attacks while
//! maintaining reasonable performance for interactive use.

use anyhow::{Result, anyhow, ensure};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_THREADS, ARGON_TIME};

/// Password-based key derivation using Argon2id.
///
/// Takes a password and salt, produces a cryptographically secure key
/// suitable for use with encryption algorithms.
pub struct Derive {
    /// The password to derive from (stored as Vec for ownership).
    key: Vec<u8>,
}

impl Derive {
    /// Creates a new derivation context from a password.
    ///
    /// # Arguments
    ///
    /// * `key` - The password or input key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty.
    pub fn new(key: &[u8]) -> Result<Self> {
        ensure!(!key.is_empty(), "key cannot be empty");
        Ok(Self { key: key.to_vec() })
    }

    /// Derives a cryptographic key using Argon2id with the given salt.
    ///
    /// Argon2id is the winner of the Password Hashing Competition and provides
    /// strong protection against GPU/ASIC attacks through:
    /// - Memory-hardness: Uses 64 MB to resist hardware attacks
    /// - Time complexity: 3 iterations for moderate cost
    /// - Parallelism: 4 threads for efficient single-machine use
    ///
    /// The key derivation process:
    /// 1. Password + salt → Argon2id hash → 64-byte derived key
    /// 2. The key is split: first 32 bytes for encryption, last 32 for HMAC
    ///
    /// # Arguments
    ///
    /// * `salt` - The salt for key derivation (should be unique per file).
    ///
    /// # Returns
    ///
    /// A 64-byte derived key.
    ///
    /// # Errors
    ///
    /// Returns an error if parameter configuration or hashing fails.
    pub fn derive_with_salt(&self, salt: &[u8]) -> Result<[u8; ARGON_KEY_LEN]> {
        // Configure Argon2id parameters:
        // - m_cost: 64 MB of memory (ARGON_MEMORY)
        // - t_cost: 3 iterations (ARGON_TIME)
        // - p_cost: 4 parallel lanes (ARGON_THREADS)
        // - output: 64 bytes (ARGON_KEY_LEN)
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameter: {e}"))?;

        // Create Argon2id hasher with version V0x13 (latest stable).
        // Version V0x13 prevents downgrade attacks.
        let argon2 = Argon2::new(Argon2id, V0x13, params);

        // Pre-allocate output buffer for the derived key.
        // This prevents timing attacks based on memory allocation.
        let mut key = [0u8; ARGON_KEY_LEN];

        // Perform key derivation:
        // hash_password_into fills the output buffer with the derived key.
        // This combines password and salt using the configured parameters.
        argon2.hash_password_into(&self.key, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {e}"))?;

        Ok(key)
    }

    /// Generates a cryptographically secure random salt.
    ///
    /// Uses the operating system's secure random number generator
    /// (getrandom with OsRng).
    ///
    /// # Type Parameters
    ///
    /// * `N` - The size of the salt in bytes.
    ///
    /// # Returns
    ///
    /// An array of N random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the random number generator fails.
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {e}"))?;
        Ok(bytes)
    }
}
