use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::Secret;
use crate::validation::KeyBytes32;

type HkdfSha256 = Hkdf<Sha256>;

pub struct DerivedKeys {
    pub first_key: Secret,
    pub second_key: Secret,
    pub third_key: Secret,
}

pub struct Key {
    key: Secret,
}

impl Key {
    pub fn new(key: &Secret) -> Result<Self> {
        let key = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn derive_keys(&self, salt: &[u8]) -> Result<DerivedKeys> {
        let master_key = self.derive_master_key(salt).context("failed to derive master key")?;
        let hkdf = HkdfSha256::new(Some(salt), master_key.expose_secret());

        let expand_key = |info: &[u8]| -> Result<Secret> {
            let mut buffer = vec![0u8; KEY_LEN];
            hkdf.expand(info, &mut buffer).context("failed to expand hkdf key")?;

            Ok(Secret::new(buffer))
        };

        Ok(DerivedKeys { first_key: expand_key(&KDF_INFO[0])?, second_key: expand_key(&KDF_INFO[1])?, third_key: expand_key(&KDF_INFO[2])? })
    }

    fn derive_master_key(&self, salt: &[u8]) -> Result<Secret> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut buffer = vec![0u8; ARGON2_KEY_LEN];
        argon2.hash_password_into(self.key.expose_secret(), salt, &mut buffer).context("failed to stretch key with argon2")?;

        Ok(Secret::new(buffer))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SysRng.try_fill_bytes(&mut bytes).context("failed to generate salt")?;

        Ok(bytes)
    }
}
