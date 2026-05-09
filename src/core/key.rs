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

pub struct DerivedKeys {
    pub first_key: SecretBytes,
    pub second_key: SecretBytes,
    pub third_key: SecretBytes,
}

pub struct Key {
    key: SecretBytes,
}

impl Key {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn derive_keys(&self, salt: &[u8]) -> Result<DerivedKeys> {
        let ikm = self.derive_ikm(salt)?;
        let hkdf = HkdfSha256::new(Some(salt), ikm.expose_secret());

        let result = |info: &[u8]| -> Result<SecretBytes> {
            let mut buffer = vec![0u8; KEY_LEN];
            hkdf.expand(info, &mut buffer).context("failed to expand hkdf key")?;
            Ok(SecretBytes::new(buffer))
        };

        Ok(DerivedKeys { first_key: result(&KDF_INFO[0])?, second_key: result(&KDF_INFO[1])?, third_key: result(&KDF_INFO[2])? })
    }

    fn derive_ikm(&self, salt: &[u8]) -> Result<SecretBytes> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut buffer = vec![0u8; ARGON2_KEY_LEN];
        argon2.hash_password_into(self.key.expose_secret(), salt, &mut buffer).context("failed to stretch key with argon2")?;

        Ok(SecretBytes::new(buffer))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        SysRng.try_fill_bytes(&mut bytes).context("failed to generate salt")?;

        Ok(bytes)
    }
}
