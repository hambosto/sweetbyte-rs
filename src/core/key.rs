use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::Secret;
use crate::validation::KeyBytes32;

pub struct DerivedKeys {
    pub primary_key: Secret,
    pub secondary_key: Secret,
    pub signer_key: Secret,
}

struct KeyLen(usize);

impl KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub struct Key {
    key: Secret,
}

impl Key {
    pub fn new(key: &Secret) -> Result<Self> {
        let inner = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must be exactly 32 bytes")?;

        Ok(Self { key: inner.into_secret() })
    }

    pub fn derive_keys(&self, salt: &Secret) -> Result<DerivedKeys> {
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

        let primary_okm = prk.expand(&[&KDF_INFO[0]], KeyLen(KEY_LEN)).context("failed to expand primary key")?;
        primary_okm.fill(primary_key.expose_secret_mut()).context("failed to fill primary key")?;

        let secondary_okm = prk.expand(&[&KDF_INFO[1]], KeyLen(KEY_LEN)).context("failed to expand secondary key")?;
        secondary_okm.fill(secondary_key.expose_secret_mut()).context("failed to fill secondary key")?;

        let signer_okm = prk.expand(&[&KDF_INFO[2]], KeyLen(KEY_LEN)).context("failed to expand signer key")?;
        signer_okm.fill(signer_key.expose_secret_mut()).context("failed to fill signer key")?;

        Ok(DerivedKeys { primary_key, secondary_key, signer_key })
    }

    pub fn generate_salt(size: usize) -> Result<Secret> {
        let mut buffer = vec![0u8; size];

        SystemRandom::new().fill(&mut buffer).context("failed to generate salt")?;

        Ok(Secret::new(buffer))
    }
}
