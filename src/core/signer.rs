use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::secret::SecretBytes;
use crate::validation::NonEmptyKey;

type HmacSha256 = Hmac<Sha256>;

pub struct Signer {
    key: SecretBytes,
}

impl Signer {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(self.key.expose_secret()).context("failed to initialize signer")?;
        parts.iter().filter(|p| !p.is_empty()).for_each(|p| mac.update(p));

        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts).map(|computed| expected.ct_eq(&computed).into()).unwrap_or(false)
    }
}
