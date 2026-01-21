use anyhow::{Result, anyhow, ensure};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_THREADS, ARGON_TIME};

pub struct Kdf([u8; ARGON_KEY_LEN]);

impl Kdf {
    pub fn derive(password: &[u8], salt: &[u8]) -> Result<Self> {
        ensure!(!password.is_empty(), "password cannot be empty");

        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN)).map_err(|e| anyhow!("invalid argon2 parameters: {e}"))?;

        let argon2 = Argon2::new(Argon2id, V0x13, params);

        let mut key = [0u8; ARGON_KEY_LEN];

        argon2.hash_password_into(password, salt, &mut key).map_err(|e| anyhow!("key derivation failed: {e}"))?;

        Ok(Self(key))
    }

    #[inline]
    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| anyhow!("rng failed: {e}"))?;
        Ok(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; ARGON_KEY_LEN] {
        &self.0
    }
}
