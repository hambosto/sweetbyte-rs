use anyhow::Result;
use ring::hmac::{Context, HMAC_SHA256, Key};
use subtle::ConstantTimeEq;

use crate::secret::SecretBytes;

pub struct Signer {
    key: SecretBytes,
}

impl Signer {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(!key.is_empty(), "invalid key length");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Vec<u8> {
        let key = Key::new(HMAC_SHA256, self.key.expose_secret());
        let mut ctx = Context::with_key(&key);

        for part in parts.iter().copied().filter(|p| !p.is_empty()) {
            ctx.update(part);
        }

        ctx.sign().as_ref().to_vec()
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        let computed = self.compute_parts(parts);
        expected.ct_eq(&computed).into()
    }
}
