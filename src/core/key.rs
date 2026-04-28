use anyhow::{Context, Result};
use rand::rngs::SysRng;
use rand::TryRng;

use crate::config::{SCRYPT_KEY_LEN, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R};
use crate::secret::SecretBytes;

pub struct Key {
    key: SecretBytes,
}

impl Key {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(!key.is_empty(), "invalid key length");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn derive_key(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P).context("invalid parameters")?;

        let mut derived_key = vec![0u8; SCRYPT_KEY_LEN];
        scrypt::scrypt(self.key.expose_secret(), salt, &params, &mut derived_key).context("key derivation failed")?;

        Ok(SecretBytes::new(derived_key))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SysRng.try_fill_bytes(&mut bytes).context("salt generation failed")?;

        Ok(bytes)
    }
}
