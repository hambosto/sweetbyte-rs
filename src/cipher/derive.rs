//! Password-based key derivation function (PBKDF) implementation.
//!
//! This module handles the secure derivation of cryptographic keys from user passwords
//! using the **Argon2id** algorithm. Argon2id is the winner of the Password Hashing Competition
//! and provides state-of-the-art resistance against:
//! - **GPU cracking attacks** (via memory hardness)
//! - **Side-channel attacks** (via data-independent memory access)
//! - **Time-memory trade-off attacks**
//!
//! # Parameters
//!
//! The derivation parameters (memory, time, parallelism) are configurable but default
//! to secure values defined in [`crate::config`].

use anyhow::{Result, anyhow, ensure};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::ARGON_KEY_LEN;

/// A context for deriving keys from a specific password.
pub struct Derive {
    /// The source password bytes.
    key: Vec<u8>,
}

impl Derive {
    /// Creates a new derivation context with the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if the password is empty.
    #[inline]
    pub fn new(key: &[u8]) -> Result<Self> {
        // Enforce that the password is not empty.
        // Empty passwords have zero entropy and are trivially guessable.
        ensure!(!key.is_empty(), "key cannot be empty");

        Ok(Self { key: key.to_vec() })
    }

    /// Derives a cryptographic key using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `salt` - A unique random salt (must be at least 16 bytes).
    /// * `memory` - Memory cost in KiB (e.g., 65536 for 64 MiB).
    /// * `time` - Time cost (number of passes).
    /// * `parallelism` - Degree of parallelism (number of threads).
    ///
    /// # Returns
    ///
    /// Returns a 64-byte key (512 bits).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parameters are invalid (e.g., memory too small).
    /// - The hashing operation fails.
    pub fn derive_key(&self, salt: &[u8], memory: u32, time: u32, parallelism: u32) -> Result<[u8; ARGON_KEY_LEN]> {
        // Configure Argon2 parameters.
        // We explicitly specify the output length (ARGON_KEY_LEN).
        // This validation step ensures we don't proceed with insecure or invalid params.
        let params = Params::new(memory, time, parallelism, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameter: {e}"))?;

        // Initialize the Argon2 context.
        // - Algorithm::Argon2id: Hybrid mode, best for password hashing.
        // - Version::V0x13: The latest version of the algorithm.
        let argon2 = Argon2::new(Argon2id, V0x13, params);

        // Prepare the output buffer.
        let mut key = [0u8; ARGON_KEY_LEN];

        // Perform the derivation.
        // This is a CPU and memory-intensive operation designed to be slow.
        // It mixes the password and salt according to the cost parameters.
        argon2.hash_password_into(&self.key, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {e}"))?;

        Ok(key)
    }

    /// Generates a cryptographically secure random salt.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::cipher::Derive;
    ///
    /// let salt = Derive::generate_salt::<32>().unwrap();
    /// assert_eq!(salt.len(), 32);
    /// ```
    #[inline]
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        // Allocate a zero-initialized buffer on the stack.
        let mut bytes = [0u8; N];

        // Fill the buffer with random bytes from the OS's CSPRNG.
        // Using OsRng ensures high-quality entropy suitable for cryptographic salts.
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {e}"))?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_new_valid() {
        let key = b"password";
        let derive = Derive::new(key);
        assert!(derive.is_ok());
    }

    #[test]
    fn test_derive_new_empty() {
        assert!(Derive::new(&[]).is_err());
    }

    #[test]
    fn test_generate_salt() {
        let salt = Derive::generate_salt::<16>();
        assert!(salt.is_ok());
        let salt = salt.unwrap();
        assert_eq!(salt.len(), 16);

        let salt2 = Derive::generate_salt::<16>().unwrap();
        assert_ne!(salt, salt2);
    }

    #[test]
    fn test_derive_key_deterministic() {
        // Verify that the same inputs produce the same output (determinism).
        let password = b"password123";
        let derive = Derive::new(password).unwrap();
        let salt = [1u8; 16];
        let memory = 1024;
        let time = 1;
        let parallelism = 1;

        let key1 = derive.derive_key(&salt, memory, time, parallelism).unwrap();
        let key2 = derive.derive_key(&salt, memory, time, parallelism).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), ARGON_KEY_LEN);
    }

    #[test]
    fn test_derive_key_different_salt() {
        // Verify that different salts produce different keys.
        let password = b"password123";
        let derive = Derive::new(password).unwrap();
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let memory = 1024;
        let time = 1;
        let parallelism = 1;

        let key1 = derive.derive_key(&salt1, memory, time, parallelism).unwrap();
        let key2 = derive.derive_key(&salt2, memory, time, parallelism).unwrap();

        assert_ne!(key1, key2);
    }
}
