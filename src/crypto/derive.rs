//! Key derivation using Argon2id.

use anyhow::{Result, bail};
use argon2::{Argon2, Params, Version};
use rand::Rng;

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};

/// Derives a key from a password and salt using Argon2id.
///
/// # Arguments
/// * `password` - The password bytes
/// * `salt` - The salt bytes (must be ARGON_SALT_LEN bytes)
///
/// # Returns
/// A 64-byte derived key
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; ARGON_KEY_LEN]> {
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    if salt.len() != ARGON_SALT_LEN {
        bail!("expected {} bytes salt, got {}", ARGON_SALT_LEN, salt.len());
    }

    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {:?}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; ARGON_KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {:?}", e))?;

    Ok(key)
}

/// Generates cryptographically secure random bytes.
///
/// # Returns
/// An array of N random bytes
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rand::rng().fill(&mut bytes);
    Ok(bytes)
}

/// Generates a random salt for key derivation.
pub fn generate_salt() -> Result<[u8; ARGON_SALT_LEN]> {
    random_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let password = b"test_password";
        let salt = random_bytes::<ARGON_SALT_LEN>().unwrap();
        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), ARGON_KEY_LEN);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0u8; ARGON_SALT_LEN];
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_empty_password() {
        let salt = [0u8; ARGON_SALT_LEN];
        assert!(derive_key(b"", &salt).is_err());
    }

    #[test]
    fn test_derive_key_invalid_salt() {
        let password = b"test_password";
        let salt = [0u8; 16]; // Wrong size
        assert!(derive_key(password, &salt).is_err());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1: [u8; 32] = random_bytes().unwrap();
        let bytes2: [u8; 32] = random_bytes().unwrap();
        // Extremely unlikely to be equal
        assert_ne!(bytes1, bytes2);
    }
}
