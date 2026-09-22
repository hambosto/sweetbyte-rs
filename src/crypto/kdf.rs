use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::core::{KeyBytes, Secret};

pub(crate) struct KeyDerivation {
    key: Secret,
}

impl KeyDerivation {
    pub(crate) fn new(secret: &Secret) -> Result<Self> {
        let key = KeyBytes::try_new(secret.expose_secret().into()).context("invalid KDF input key")?;

        Ok(Self { key: key.into() })
    }

    pub(crate) fn derive_keys(&self, salt: &Secret) -> Result<(Secret, Secret, Secret)> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("failed to init password hasher")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut stretched = vec![u8::MIN; ARGON2_KEY_LEN];
        argon2
            .hash_password_into(self.key.expose_secret(), salt.expose_secret(), &mut stretched)
            .context("failed to hash password")?;
        let hkdf = Hkdf::<Sha256>::new(Some(salt.expose_secret()), &stretched);

        let mut primary_key = vec![u8::MIN; KEY_LEN];
        hkdf.expand(&KDF_INFO[0], &mut primary_key).context("failed to derive AES key")?;

        let mut secondary_key = vec![u8::MIN; KEY_LEN];
        hkdf.expand(&KDF_INFO[1], &mut secondary_key).context("failed to derive XChaCha key")?;

        let mut signer_key = vec![u8::MIN; KEY_LEN];
        hkdf.expand(&KDF_INFO[2], &mut signer_key).context("failed to derive auth key")?;

        Ok((Secret::from(primary_key), Secret::from(secondary_key), Secret::from(signer_key)))
    }

    pub(crate) fn generate_salt(salt_len: usize) -> Result<Secret> {
        let mut salt = vec![u8::MIN; salt_len];

        SysRng.try_fill_bytes(&mut salt).context("failed to generate salt")?;

        Ok(Secret::from(salt))
    }
}
