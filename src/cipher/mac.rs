use anyhow::{Context, Result};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::secret::SecretBytes;

pub struct Mac {
    key: SecretBytes,
}

impl Mac {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            anyhow::bail!("empty mac key");
        }

        Ok(Self { key: SecretBytes::new(key) })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose_secret()).context("create hmac")?;

        for part in parts.iter().copied().filter(|p| !p.is_empty()) {
            mac.update(part);
        }

        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        let computed = match self.compute_parts(parts) {
            Ok(computed) => computed,
            Err(error) => {
                tracing::error!("failed to compute MAC parts: {error}");
                return false;
            }
        };

        bool::from(expected.ct_eq(&computed))
    }
}
