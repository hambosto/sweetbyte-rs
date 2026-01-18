use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm::Argon2id, Argon2, Params, Version::V0x13};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KDF([u8; ARGON_KEY_LEN]);

impl KDF {
    pub fn derive(password: &[u8], salt: &[u8]) -> Result<Self> {
        if password.is_empty() {
            bail!("password cannot be empty");
        }

        if salt.len() != ARGON_SALT_LEN {
            bail!("expected {} bytes salt, got {}", ARGON_SALT_LEN, salt.len());
        }

        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameters: {}", e))?;
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        let mut key = [0u8; ARGON_KEY_LEN];
        argon2.hash_password_into(password, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {}", e))?;

        Ok(Self(key))
    }

    #[inline]
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {}", e))?;
        Ok(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; ARGON_KEY_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_valid_password_and_salt() {
        let password = b"supersecret";
        let salt = KDF::generate_salt::<ARGON_SALT_LEN>().expect("salt generation failed");

        let key = KDF::derive(password, &salt).expect("key derivation failed");
        assert_eq!(key.as_bytes().len(), ARGON_KEY_LEN);
    }

    #[test]
    fn derive_empty_password_should_fail() {
        let password = b"";
        let salt = KDF::generate_salt::<ARGON_SALT_LEN>().expect("salt generation failed");

        let result = KDF::derive(password, &salt);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "password cannot be empty");
    }

    #[test]
    fn derive_incorrect_salt_length_should_fail() {
        let password = b"supersecret";
        let short_salt = [0u8; ARGON_SALT_LEN - 1];

        let result = KDF::derive(password, &short_salt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected"));
    }

    #[test]
    fn generate_salt_returns_correct_length() {
        const LEN: usize = 16;
        let salt = KDF::generate_salt::<LEN>().expect("salt generation failed");
        assert_eq!(salt.len(), LEN);
    }

    #[test]
    fn derive_is_deterministic_for_same_input() {
        let password = b"samepassword";
        let salt = KDF::generate_salt::<ARGON_SALT_LEN>().expect("salt generation failed");

        let key1 = KDF::derive(password, &salt).expect("key derivation failed");
        let key2 = KDF::derive(password, &salt).expect("key derivation failed");

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_differs_with_different_salt() {
        let password = b"samepassword";
        let salt1 = KDF::generate_salt::<ARGON_SALT_LEN>().expect("salt generation failed");
        let salt2 = KDF::generate_salt::<ARGON_SALT_LEN>().expect("salt generation failed");

        let key1 = KDF::derive(password, &salt1).expect("key derivation failed");
        let key2 = KDF::derive(password, &salt2).expect("key derivation failed");

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
