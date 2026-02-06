use anyhow::{Context, Result};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::rand_core::{OsRng, TryRngCore};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_PARALLELISM, ARGON_TIME};

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

    pub fn derive_key(&self, salt: &[u8]) -> Result<Vec<u8>> {
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_PARALLELISM, Some(ARGON_KEY_LEN)).map_err(|error| anyhow::anyhow!("invalid argon2 params: {error}"))?;
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        let mut derived_key = vec![0u8; ARGON_KEY_LEN];

        argon2
            .hash_password_into(&self.key, salt, &mut derived_key)
            .map_err(|error| anyhow::anyhow!("derive argon2 key: {error}"))?;

        Ok(derived_key)
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; size];

        OsRng.try_fill_bytes(&mut bytes).context("generate salt")?;

        Ok(bytes)
    }
}
