use anyhow::{Result, bail};
use hmac::{Hmac, Mac as HmacMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mac([u8; MAC_SIZE]);

impl Mac {
    pub fn compute(key: &[u8], parts: &[&[u8]]) -> Result<Self> {
        if key.is_empty() {
            bail!("mac key cannot be empty");
        }

        let mut mac = HmacSha256::new_from_slice(key).expect("hmac-sha256 accepts any key length");
        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        Ok(Self(mac.finalize().into_bytes().into()))
    }

    #[inline]
    pub fn compute_bytes(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        Self::compute(key, parts).map(|mac| mac.0)
    }

    pub fn verify(&self, key: &[u8], parts: &[&[u8]]) -> Result<()> {
        let computed = Self::compute(key, parts)?;

        if !bool::from(self.0.ct_eq(&computed.0)) {
            bail!("mac verification failed");
        }

        Ok(())
    }

    pub fn verify_bytes(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        if expected.len() != MAC_SIZE {
            bail!("invalid mac length: expected {}, got {}", MAC_SIZE, expected.len());
        }

        let array: [u8; MAC_SIZE] = expected.try_into().expect("length check ensure conversion succeeds");
        let expected_mac = Self(array);
        expected_mac.verify(key, parts)
    }

    #[inline]
    #[must_use]
    pub fn verify_magic(actual: &[u8], expected: &[u8]) -> bool {
        bool::from(actual.ct_eq(expected))
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MAC_SIZE] {
        &self.0
    }
}
