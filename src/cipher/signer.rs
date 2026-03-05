use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::secret::SecretBytes;

type HmacSha256 = Hmac<Sha256>;

pub struct Signer {
    key: SecretBytes,
}

impl Signer {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(!key.is_empty(), "Cannot use empty key for HMAC");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(self.key.expose_secret()).context("Failed to initialize HMAC signer")?;

        parts.iter().copied().filter(|p| !p.is_empty()).for_each(|p| mac.update(p));

        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts)
            .inspect_err(|error| tracing::error!("HMAC computation failed: {}", error))
            .is_ok_and(|computed| expected.ct_eq(&computed).into())
    }
}
