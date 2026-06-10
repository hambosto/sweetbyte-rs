use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::config::{ARGON2_KEY_LEN, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KDF_INFO, KEY_LEN};
use crate::secret::Secret;
use crate::validation::KeyBytes32;

pub struct DerivedKeys {
    pub first_key: Secret,
    pub second_key: Secret,
    pub third_key: Secret,
}

pub struct Key(Secret);

struct HkdfKeyLen(usize);

impl KeyType for HkdfKeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl Key {
    pub fn new(key: &Secret) -> Result<Self> {
        let inner = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must be exactly 32 bytes")?;

        Ok(Self(inner.into_secret()))
    }

    pub fn derive_keys(&self, salt: &[u8]) -> Result<DerivedKeys> {
        let master = self.stretch(salt)?;
        let prk = Salt::new(HKDF_SHA256, salt).extract(master.expose_secret());
        let keys: Vec<Secret> = KDF_INFO.iter().map(|info| expand_key(&prk, info)).collect::<Result<Vec<Secret>>>()?;
        let [first_key, second_key, third_key] = keys.try_into().map_err(|keys: Vec<Secret>| anyhow::anyhow!("expected 3 keys, got {}", keys.len()))?;

        Ok(DerivedKeys { first_key, second_key, third_key })
    }

    fn stretch(&self, salt: &[u8]) -> Result<Secret> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_KEY_LEN)).context("invalid argon2 parameters")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut buffer = vec![0u8; ARGON2_KEY_LEN];
        argon2.hash_password_into(self.0.expose_secret(), salt, &mut buffer).context("failed to stretch key with argon2")?;

        Ok(Secret::new(buffer))
    }

    pub fn generate_salt(size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];

        SystemRandom::new().fill(&mut buffer).context("failed to generate salt")?;

        Ok(buffer)
    }
}

fn expand_key(prk: &Prk, info: &[u8]) -> Result<Secret> {
    let kdf_info = &[info];
    let okm = prk.expand(kdf_info, HkdfKeyLen(KEY_LEN)).context("failed to expand hkdf key")?;

    let mut buffer = vec![0u8; KEY_LEN];
    okm.fill(&mut buffer).context("failed to fill hkdf")?;

    Ok(Secret::new(buffer))
}
