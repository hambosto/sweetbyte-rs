use anyhow::{Context, Result};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use rand::TryRng;
use rand::rngs::SysRng;

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_PARALLELISM, ARGON_TIME};
use crate::secret::SecretBytes;

pub struct Derive {
    key: SecretBytes,
}

impl Derive {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            anyhow::bail!("empty key");
        }

        Ok(Self { key: SecretBytes::new(key) })
    }

    pub fn derive_key(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_PARALLELISM, Some(ARGON_KEY_LEN)).map_err(|error| anyhow::anyhow!("invalid argon2 params: {error}"))?;
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        let mut derived_key = vec![0u8; ARGON_KEY_LEN];

        argon2
            .hash_password_into(self.key.expose_secret(), salt, &mut derived_key)
            .map_err(|error| anyhow::anyhow!("derive argon2 key: {error}"))?;

        Ok(SecretBytes::from_vec(derived_key))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; size];

        SysRng.try_fill_bytes(&mut bytes).context("generate salt")?;

        Ok(bytes)
    }
}
