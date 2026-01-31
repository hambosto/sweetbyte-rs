use anyhow::{Context, Result};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::ARGON_KEY_LEN;

pub struct Derive {
    key: Vec<u8>,
}

impl Derive {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            anyhow::bail!("empty key");
        }

        Ok(Self { key: key.to_vec() })
    }

    pub fn derive_key(&self, salt: &[u8], memory: u32, time: u32, parallelism: u32) -> Result<[u8; ARGON_KEY_LEN]> {
        let params = Params::new(memory, time, parallelism, Some(ARGON_KEY_LEN)).map_err(|error| anyhow::anyhow!("invalid argon2 params: {error}"))?;
        let argon2 = Argon2::new(Argon2id, V0x13, params);

        let mut derived_key = [0u8; ARGON_KEY_LEN];
        argon2
            .hash_password_into(&self.key, salt, &mut derived_key)
            .map_err(|error| anyhow::anyhow!("derive argon2 key: {error}"))?;

        Ok(derived_key)
    }

    pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];

        OsRng.try_fill_bytes(&mut bytes).context("generate salt")?;

        Ok(bytes)
    }
}
