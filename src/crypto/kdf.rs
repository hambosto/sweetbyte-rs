//! Argon2id key derivation.

use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};

/// Argon2id time cost (iterations).
const ARGON_TIME: u32 = 3;
/// Argon2id memory cost in KiB (64 MB).
const ARGON_MEMORY: u32 = 64 * 1024;
/// Argon2id parallelism (threads).
const ARGON_THREADS: u32 = 4;

/// Output key length in bytes.
pub const ARGON_KEY_LEN: usize = 64;
/// Salt length in bytes.
pub const ARGON_SALT_LEN: usize = 32;

/// Derives a cryptographic key from a password using Argon2id.
///
/// Returns a 64-byte key derived from the password and salt.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; ARGON_KEY_LEN]> {
    anyhow::ensure!(!password.is_empty(), "password cannot be empty");
    anyhow::ensure!(
        salt.len() == ARGON_SALT_LEN,
        "salt must be {ARGON_SALT_LEN} bytes, got {}",
        salt.len()
    );

    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt_string =
        SaltString::encode_b64(salt).map_err(|e| anyhow::anyhow!("failed to encode salt: {e}"))?;

    let hash = argon2
        .hash_password(password, &salt_string)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {e}"))?;

    let hash_bytes = hash.hash.context("no hash produced")?;

    let bytes = hash_bytes.as_bytes();
    anyhow::ensure!(
        bytes.len() >= ARGON_KEY_LEN,
        "hash too short: got {} bytes, expected {ARGON_KEY_LEN}",
        bytes.len()
    );

    let mut key = [0u8; ARGON_KEY_LEN];
    key.copy_from_slice(&bytes[..ARGON_KEY_LEN]);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_derive_key() {
        let password = b"testpassword";
        let salt = random_bytes(ARGON_SALT_LEN).unwrap();
        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), ARGON_KEY_LEN);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"testpassword";
        let salt = vec![0u8; ARGON_SALT_LEN];
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_empty_password() {
        let salt = vec![0u8; ARGON_SALT_LEN];
        assert!(derive_key(&[], &salt).is_err());
    }

    #[test]
    fn test_invalid_salt_length() {
        assert!(derive_key(b"password", &[0u8; 16]).is_err());
        assert!(derive_key(b"password", &[0u8; 64]).is_err());
    }
}
