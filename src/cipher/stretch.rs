use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::Secret;
use crate::validation::NonEmptyKey;

pub(crate) struct ExtendedKeys {
    pub(crate) primary_key: Secret,
    pub(crate) secondary_key: Secret,
    pub(crate) signer_key: Secret,
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

pub(crate) struct Stretch {
    key: Secret,
}

impl Stretch {
    pub(crate) fn new(key: &Secret) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub(crate) fn derive_keys(&self, salt: &Secret) -> Result<ExtendedKeys> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut stretched = vec![0u8; ARGON2_KEY_LEN];
        argon2
            .hash_password_into(self.key.expose_secret(), salt.expose_secret(), &mut stretched)
            .context("failed to stretch key with argon2")?;

        let prk = Salt::new(HKDF_SHA256, salt.expose_secret()).extract(&stretched);

        let mut primary_key = Secret::new(vec![0u8; KEY_LEN]);
        let mut secondary_key = Secret::new(vec![0u8; KEY_LEN]);
        let mut signer_key = Secret::new(vec![0u8; KEY_LEN]);

        let primary_okm = prk.expand(&[&KDF_INFO[0]], Len(KEY_LEN)).context("failed to expand primary key")?;
        primary_okm.fill(primary_key.expose_secret_mut()).context("failed to fill primary key")?;

        let secondary_okm = prk.expand(&[&KDF_INFO[1]], Len(KEY_LEN)).context("failed to expand secondary key")?;
        secondary_okm.fill(secondary_key.expose_secret_mut()).context("failed to fill secondary key")?;

        let signer_okm = prk.expand(&[&KDF_INFO[2]], Len(KEY_LEN)).context("failed to expand signer key")?;
        signer_okm.fill(signer_key.expose_secret_mut()).context("failed to fill signer key")?;

        Ok(ExtendedKeys { primary_key, secondary_key, signer_key })
    }

    pub(crate) fn generate_salt(salt_size: usize) -> Result<Secret> {
        let mut salt_bytes = vec![0u8; salt_size];

        SystemRandom::new().fill(&mut salt_bytes).context("failed to generate salt")?;

        Ok(Secret::new(salt_bytes))
    }
}
