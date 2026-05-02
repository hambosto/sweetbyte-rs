use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRng;
use rand::rngs::SysRng;

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST};
use crate::secret::SecretBytes;
use crate::validation::{IntoSecretBytes, NonEmptyKey};

pub struct Key {
    key: SecretBytes,
}

impl Key {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;
        Ok(Self { key: key.into_secret() })
    }

    pub fn derive_key(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = vec![0u8; ARGON2_KEY_LEN];
        argon2.hash_password_into(self.key.expose_secret(), salt, &mut derived_key).context("failed to derive key")?;

        Ok(SecretBytes::new(derived_key))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SysRng.try_fill_bytes(&mut bytes).context("failed to generate salt")?;

        Ok(bytes)
    }
}
