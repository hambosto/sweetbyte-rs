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

        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        Ok(mac.finalize().into_bytes().into())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        if expected.len() != MAC_SIZE {
            anyhow::bail!("invalid mac length");
        }

        let computed_parts = self.compute_parts(parts)?;
        let expected: [u8; MAC_SIZE] = expected.try_into().context("convert mac")?;

        if !bool::from(expected.ct_eq(&computed_parts)) {
            anyhow::bail!("mac mismatch");
        }

        Ok(())
    }
}
