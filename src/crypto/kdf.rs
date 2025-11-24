//! Argon2id key derivation.

use anyhow::{Context, Result};
use argon2::{
    Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};

// Argon2id time cost (iterations) - Determines how many times the algorithm runs.
const ARGON_TIME: u32 = 3;
// Argon2id memory cost in KiB (64 MB). This controls how much memory is used by the algorithm.
const ARGON_MEMORY: u32 = 64 * 1024;
// Argon2id parallelism (threads) - Number of threads the algorithm can use.
const ARGON_THREADS: u32 = 4;

// Output key length in bytes (64 bytes)
pub const ARGON_KEY_LEN: usize = 64;
// Salt length in bytes (32 bytes)
pub const ARGON_SALT_LEN: usize = 32;

/// Derives a cryptographic key from a password using the Argon2id algorithm.
///
/// This function uses the Argon2id key derivation function (KDF) to derive a secure key from a
/// password and salt. The function applies a configurable time cost, memory cost, and parallelism
/// level to make it resistant to brute-force and other attacks.
///
/// # Arguments
/// * `password` - The password used to derive the key.
/// * `salt` - A random salt value to protect against rainbow table attacks.
///
/// # Returns
/// A result containing a 64-byte derived key, or an error if the process fails.
///
/// # Notes
/// - The salt should be random and unique for each password derivation to prevent rainbow table
///   attacks.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; ARGON_KEY_LEN]> {
    // Ensure the password is not empty
    anyhow::ensure!(!password.is_empty(), "password cannot be empty");

    // Ensure the salt has the correct length (32 bytes)
    anyhow::ensure!(
        salt.len() == ARGON_SALT_LEN,
        "salt must be {ARGON_SALT_LEN} bytes, got {}",
        salt.len()
    );

    // Set up the Argon2 parameters (time cost, memory cost, threads, and key length)
    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;

    // Initialize Argon2id with the given parameters
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Encode the salt as a base64 string (required for the Argon2 library)
    let salt_string =
        SaltString::encode_b64(salt).map_err(|e| anyhow::anyhow!("failed to encode salt: {e}"))?;

    // Hash the password with the salt using Argon2id
    let hash = argon2
        .hash_password(password, &salt_string)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {e}"))?;

    // Retrieve the generated hash as bytes
    let hash_bytes = hash.hash.context("no hash produced")?;

    // Ensure the hash is long enough to provide the required output key length
    let bytes = hash_bytes.as_bytes();
    anyhow::ensure!(
        bytes.len() >= ARGON_KEY_LEN,
        "hash too short: got {} bytes, expected {ARGON_KEY_LEN}",
        bytes.len()
    );

    // Copy the first `ARGON_KEY_LEN` bytes of the hash into the key array
    let mut key = [0u8; ARGON_KEY_LEN];
    key.copy_from_slice(&bytes[..ARGON_KEY_LEN]);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    /// Test the key derivation process to ensure it produces a 64-byte key.
    #[test]
    fn test_derive_key() {
        let password = b"testpassword"; // Example password
        let salt = random_bytes(ARGON_SALT_LEN).unwrap(); // Generate a random salt
        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), ARGON_KEY_LEN); // Ensure the key has the correct length
    }

    /// Test that key derivation is deterministic given the same password and salt.
    #[test]
    fn test_derive_key_deterministic() {
        let password = b"testpassword";
        let salt = vec![0u8; ARGON_SALT_LEN]; // Use a fixed salt
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();
        assert_eq!(key1, key2); // Ensure the same password and salt produce the same key
    }

    /// Test that deriving a key with an empty password results in an error.
    #[test]
    fn test_empty_password() {
        let salt = vec![0u8; ARGON_SALT_LEN];
        assert!(derive_key(&[], &salt).is_err()); // Should fail due to empty password
    }

    /// Test that deriving a key with an invalid salt length results in an error.
    #[test]
    fn test_invalid_salt_length() {
        assert!(derive_key(b"password", &[0u8; 16]).is_err()); // Salt too short
        assert!(derive_key(b"password", &[0u8; 64]).is_err()); // Salt too long
    }
}
