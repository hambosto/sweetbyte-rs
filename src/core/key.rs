use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::SecretBytes;
use crate::validation::NonEmptyKey;

type HkdfSha256 = Hkdf<Sha256>;

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

    pub fn derive_hkdf_keys(&self, salt: &[u8]) -> Result<(SecretBytes, SecretBytes, SecretBytes)> {
        let hkdf = HkdfSha256::new(Some(salt), self.key.expose_secret());

        let mut first_key = vec![0u8; KEY_LEN];
        hkdf.expand(&KDF_INFO[0], &mut first_key).context("failed to derive first key")?;

        let mut second_key = vec![0u8; KEY_LEN];
        hkdf.expand(&KDF_INFO[1], &mut second_key).context("failed to derive second key")?;

        let mut third_key = vec![0u8; KEY_LEN];
        hkdf.expand(&KDF_INFO[2], &mut third_key).context("failed to derive third key")?;

        Ok((SecretBytes::new(first_key), SecretBytes::new(second_key), SecretBytes::new(third_key)))
    }
}
