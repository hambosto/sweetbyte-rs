use anyhow::{Context, Result};
use ring::hmac::{Context as HmacContext, HMAC_SHA256, Key};
use subtle::ConstantTimeEq;

use crate::secret::SecretBytes;
use crate::validation::{IntoSecretBytes, NonEmptyKey};

pub struct Signer {
    key: SecretBytes,
}

impl Signer {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = NonEmptyKey::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        let key = Key::new(HMAC_SHA256, self.key.expose_secret());

        let mut ctx = HmacContext::with_key(&key);
        parts.iter().filter(|p| !p.is_empty()).for_each(|p| ctx.update(p));

        Ok(ctx.sign().as_ref().to_vec())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts).map(|computed| expected.ct_eq(&computed).into()).unwrap_or(false)
    }
}
