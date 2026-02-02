use anyhow::{Context, Result};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

pub struct Mac {
    key: Vec<u8>,
}

impl Mac {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            anyhow::bail!("empty mac key");
        }

        Ok(Self { key: key.to_vec() })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).context("create hmac")?;

        for part in parts.iter().copied().filter(|p| !p.is_empty()) {
            mac.update(part);
        }

        Ok(mac.finalize().into_bytes().into())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        let expected: [u8; MAC_SIZE] = match expected.try_into() {
            Ok(expected) => expected,
            Err(error) => {
                tracing::error!("invalid expected MAC length: {error}");
                return false;
            }
        };

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
