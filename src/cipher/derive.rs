use anyhow::{Result, anyhow, ensure};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_THREADS, ARGON_TIME};

/// Key derivation function using Argon2id.
///
/// Provides secure password-based key derivation with configurable
/// time, memory, and parallelism parameters.
pub struct Kdf([u8; ARGON_KEY_LEN]);

impl Kdf {
    /// Derives a cryptographic key from a password and salt.
    ///
    /// Uses Argon2id, the recommended variant of Argon2, which provides
    /// resistance against both GPU and timing attacks.
    ///
    /// # Arguments
    /// * `password` - The password bytes to derive from.
    /// * `salt` - A random salt (must be at least 8 bytes, 32 bytes recommended).
    ///
    /// # Returns
    /// A Kdf instance containing the derived key, or an error.
    pub fn derive(password: &[u8], salt: &[u8]) -> Result<Self> {
        ensure!(!password.is_empty(), "password cannot be empty");

        // Configure Argon2id parameters (64 MiB memory, 3 iterations, 4 threads).
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameters: {e}"))?;
        // Create the Argon2id hasher.
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        // Allocate buffer for the derived key.
        let mut key = [0u8; ARGON_KEY_LEN];
        // Derive the key.
        argon2.hash_password_into(password, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {e}"))?;

        Ok(Self(key))
    }

    /// Generates a cryptographically secure random salt.
    ///
    /// Uses the operating system's secure random number generator.
    ///
    /// # Type Parameters
    /// * `N` - The size of the salt to generate.
    ///
    /// # Returns
    /// A byte array of N random bytes.
    #[inline]
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {e}"))?;
        Ok(bytes)
    }

    /// Returns the derived key as a byte slice.
    ///
    /// # Returns
    /// Reference to the 64-byte derived key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; ARGON_KEY_LEN] {
        &self.0
    }
}
