use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::Secret;
use crate::validation::NonEmptyKey;

pub(crate) struct DerivedKeys {
    pub(crate) primary_key: Secret,
    pub(crate) secondary_key: Secret,
    pub(crate) signer_key: Secret,
}

pub(crate) struct KeyDeriver {
    key: Secret,
}

impl KeyDeriver {
    pub(crate) fn new(key: &Secret) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub(crate) fn derive_keys(&self, salt: &Secret) -> Result<DerivedKeys> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut stretched = vec![0u8; ARGON2_KEY_LEN];
        argon2
            .hash_password_into(self.key.expose_secret(), salt.expose_secret(), &mut stretched)
            .context("failed to stretch key with argon2")?;

        let hkdf = Hkdf::<Sha256>::new(Some(salt.expose_secret()), &stretched);

        let mut primary_key = vec![0u8; KEY_LEN];
        let mut secondary_key = vec![0u8; KEY_LEN];
        let mut signer_key = vec![0u8; KEY_LEN];

        hkdf.expand(&KDF_INFO[0], &mut primary_key).context("failed to expand primary key")?;
        hkdf.expand(&KDF_INFO[1], &mut secondary_key).context("failed to expand secondary key")?;
        hkdf.expand(&KDF_INFO[2], &mut signer_key).context("failed to expand signer key")?;

        Ok(DerivedKeys { primary_key: Secret::new(primary_key), secondary_key: Secret::new(secondary_key), signer_key: Secret::new(signer_key) })
    }

    pub(crate) fn generate_salt(salt_size: usize) -> Result<Secret> {
        let mut salt_bytes = vec![0u8; salt_size];

        SysRng.try_fill_bytes(&mut salt_bytes).context("failed to generate salt")?;

        Ok(Secret::new(salt_bytes))
    }
}
