use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

pub struct Mac {
    key: Vec<u8>,
}

impl Mac {
    pub fn new(key: &[u8]) -> Result<Self> {
        ensure!(!key.is_empty(), "mac key cannot be empty");

        Ok(Self { key: key.to_vec() })
    }

    pub fn compute(&self, parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        Ok(mac.finalize().into_bytes().into())
    }

    pub fn verify(&self, expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        ensure!(expected.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, expected.len());

        let computed = self.compute(parts)?;

        let expected_array: [u8; MAC_SIZE] = expected.try_into().map_err(|_| anyhow!("failed to convert expected mac to array"))?;

        ensure!(bool::from(expected_array.ct_eq(&computed)), "mac verification failed");

        Ok(())
    }
}
