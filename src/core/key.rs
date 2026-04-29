use anyhow::{Context, Result};
use rand::TryRng;
use rand::rngs::SysRng;

use crate::config::{SCRYPT_KEY_LEN, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R};
use crate::secret::SecretBytes;
use crate::validation::NonEmptyBytes;

pub struct Key {
    key: SecretBytes,
}

impl Key {
    pub fn new(key: &[u8]) -> Result<Self> {
        let key = NonEmptyBytes::try_new(key.to_vec()).context("key must not be empty")?;

        Ok(Self { key: SecretBytes::new(key.as_ref().to_vec()) })
    }

    pub fn derive_key(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P).context("invalid scrypt parameters")?;

        let mut derived_key = vec![0u8; SCRYPT_KEY_LEN];
        scrypt::scrypt(self.key.expose_secret(), salt, &params, &mut derived_key).context("failed to derive key")?;

        Ok(SecretBytes::new(derived_key))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SysRng.try_fill_bytes(&mut bytes).context("failed to generate salt")?;

        Ok(bytes)
    }
}
