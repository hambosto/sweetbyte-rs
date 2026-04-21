use anyhow::{Context, Result};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_PARALLELISM, ARGON_TIME};
use crate::secret::SecretBytes;

pub struct Derive {
    key: SecretBytes,
}

impl Derive {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(!key.is_empty(), "empty key");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn derive_key(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_PARALLELISM, Some(ARGON_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Argon2id, V0x13, params);
        let mut derived_key = vec![0u8; ARGON_KEY_LEN];

        argon2.hash_password_into(self.key.expose_secret(), salt, &mut derived_key).context("failed to derive argon2 key")?;

        Ok(SecretBytes::new(derived_key))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SystemRandom::new().fill(&mut bytes).context("failed to generate salt")?;

        Ok(bytes)
    }
}
