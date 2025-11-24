//! Key Derivation Function (KDF) using Argon2id.
//!
//! This module implements password hashing and key derivation using the Argon2id algorithm.
//! It uses parameters compatible with the Go implementation of SweetByte.

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};

// Argon2id parameters matching Go implementation
/// Time cost (iterations).
pub const ARGON_TIME: u32 = 3;
/// Memory cost in KiB (64 MB).
pub const ARGON_MEMORY: u32 = 64 * 1024; // 64 KB
/// Parallelism (threads).
pub const ARGON_THREADS: u32 = 4;
/// Output key length in bytes.
pub const ARGON_KEY_LEN: usize = 64;
/// Salt length in bytes.
pub const ARGON_SALT_LEN: usize = 32;

/// Derives a 64-byte key from a password and salt using Argon2id.
///
/// This function uses the Argon2id algorithm with predefined parameters to derive a
/// cryptographically strong key from a password and a random salt.
///
/// # Arguments
///
/// * `password` - The password to hash.
/// * `salt` - A 32-byte random salt.
///
/// # Returns
///
/// Returns a 64-byte array containing the derived key, or an error if hashing fails.
///
/// # Errors
///
/// Returns an error if:
/// - The password is empty.
/// - The salt length is not `ARGON_SALT_LEN`.
/// - Argon2 parameter creation fails.
/// - Hashing fails.
///
/// # Examples
///
/// ```
/// use sweetbyte::crypto::kdf::{self, ARGON_SALT_LEN};
/// use sweetbyte::crypto::random;
///
/// let password = b"my_secret_password";
/// let salt = random::get_random_bytes(ARGON_SALT_LEN).unwrap();
/// let key = kdf::hash(password, &salt).unwrap();
///
/// assert_eq!(key.len(), 64);
/// ```
pub fn hash(password: &[u8], salt: &[u8]) -> anyhow::Result<[u8; ARGON_KEY_LEN]> {
    // Check if the password is empty. This is an invalid input case.
    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }

    // Ensure the salt has the correct length. It should be exactly 32 bytes.
    if salt.len() != ARGON_SALT_LEN {
        return Err(anyhow::anyhow!(
            "expected {} bytes, got {}",
            ARGON_SALT_LEN,
            salt.len()
        ));
    }

    // Create Argon2 parameters using the specified constants:
    // - Memory cost (ARGON_MEMORY)
    // - Time cost (ARGON_TIME)
    // - Parallelism (ARGON_THREADS)
    // - Output key length (ARGON_KEY_LEN)
    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("failed to create Argon2 params: {}", e))?;

    // Initialize the Argon2id instance with the created parameters.
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Encode the salt into base64 format as required by the Argon2 API.
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("failed to encode salt: {}", e))?;

    // Hash the password using Argon2id with the encoded salt.
    let hash = argon2
        .hash_password(password, &salt_string)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {}", e))?;

    // Retrieve the raw bytes of the generated hash.
    let hash_bytes = hash
        .hash
        .ok_or_else(|| anyhow::anyhow!("no hash produced"))?;

    // Initialize an array to hold the final 64-byte derived key.
    let mut key = [0u8; ARGON_KEY_LEN];

    // Convert the hash bytes to a byte slice.
    let bytes = hash_bytes.as_bytes();

    // If the hash is shorter than expected (ARGON_KEY_LEN), return an error.
    if bytes.len() < ARGON_KEY_LEN {
        return Err(anyhow::anyhow!(
            "hash too short: got {} bytes, expected {}",
            bytes.len(),
            ARGON_KEY_LEN
        ));
    }

    // Copy the first ARGON_KEY_LEN bytes of the hash into the key array.
    key.copy_from_slice(&bytes[..ARGON_KEY_LEN]);

    // Return the derived 64-byte key.
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random;

    #[test]
    fn test_hash() {
        let password = b"testpassword";
        let salt = random::get_random_bytes(ARGON_SALT_LEN).unwrap();
        let key = hash(password, &salt).unwrap();
        assert_eq!(key.len(), ARGON_KEY_LEN);
    }

    #[test]
    fn test_hash_deterministic() {
        let password = b"testpassword";
        let salt = vec![0u8; ARGON_SALT_LEN];
        let key1 = hash(password, &salt).unwrap();
        let key2 = hash(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }
}
