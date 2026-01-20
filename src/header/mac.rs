use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as HmacMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct Mac([u8; MAC_SIZE]);

impl Mac {
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; MAC_SIZE]) -> Self {
        Self(bytes)
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MAC_SIZE] {
        &self.0
    }

    pub fn compute(key: &[u8], parts: &[&[u8]]) -> Result<Self> {
        ensure!(!key.is_empty(), "mac key cannot be empty");

        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        for part in parts.iter().filter(|p| !p.is_empty()) {
            mac.update(part);
        }

        Ok(Self(mac.finalize().into_bytes().into()))
    }

    #[inline]
    pub fn compute_bytes(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        Self::compute(key, parts).map(|mac| mac.0)
    }

    pub fn verify(&self, key: &[u8], parts: &[&[u8]]) -> Result<()> {
        let computed = Self::compute(key, parts)?;

        ensure!(bool::from(self.0.ct_eq(&computed.0)), "mac verification failed");

        Ok(())
    }

    pub fn verify_bytes(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        let mac = Self::try_from(expected)?;
        mac.verify(key, parts)
    }
}

impl AsRef<[u8]> for Mac {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Mac> for [u8; MAC_SIZE] {
    #[inline]
    fn from(mac: Mac) -> Self {
        mac.0
    }
}

impl TryFrom<&[u8]> for Mac {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        ensure!(value.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, value.len());

        let array: [u8; MAC_SIZE] = value.try_into().map_err(|_| anyhow!("mac conversion failed"))?;
        Ok(Self::from_bytes(array))
    }
}
