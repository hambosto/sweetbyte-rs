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
            bail!("MAC key cannot be empty");
        }

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
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
            bail!("MAC verification failed");
        }

        Ok(())
    }

    pub fn verify_bytes(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        if expected.len() != MAC_SIZE {
            bail!("Invalid MAC length: expected {}, got {}", MAC_SIZE, expected.len());
        }

        let array: [u8; MAC_SIZE] = expected.try_into().expect("Length check ensure conversion succeeds");
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"secret_key";
    const WRONG_KEY: &[u8] = b"wrong_key";

    #[test]
    fn mac_compute_produces_correct_length() {
        let data = [b"Hello".as_slice(), b"World".as_slice()];
        let mac = Mac::compute(TEST_KEY, &data).unwrap();
        assert_eq!(mac.as_bytes().len(), MAC_SIZE);
    }

    #[test]
    fn mac_verify_succeeds_with_valid_mac() {
        let data = [b"Hello".as_slice(), b"World".as_slice()];
        let mac = Mac::compute(TEST_KEY, &data).unwrap();
        assert!(mac.verify(TEST_KEY, &data).is_ok());
    }

    #[test]
    fn mac_verify_fails_with_wrong_key() {
        let data = [b"Hello".as_slice()];
        let mac = Mac::compute(TEST_KEY, &data).unwrap();
        assert!(mac.verify(WRONG_KEY, &data).is_err());
    }

    #[test]
    fn mac_verify_fails_with_tampered_mac() {
        let data = [b"Hello".as_slice()];
        let mut mac = Mac::compute(TEST_KEY, &data).unwrap();
        mac.0[0] ^= 0xFF;
        assert!(mac.verify(TEST_KEY, &data).is_err());
    }

    #[test]
    fn compute_mac_rejects_empty_key() {
        let data = [b"Hello".as_slice()];
        assert!(Mac::compute(&[], &data).is_err());
    }

    #[test]
    fn verify_bytes_rejects_invalid_length() {
        let data = [b"Hello".as_slice()];
        let wrong_length = vec![0u8; MAC_SIZE - 1];
        assert!(Mac::verify_bytes(TEST_KEY, &wrong_length, &data).is_err());
    }

    #[test]
    fn verify_magic_returns_true_for_matching_bytes() {
        assert!(Mac::verify_magic(b"MAGIC", b"MAGIC"));
    }

    #[test]
    fn verify_magic_returns_false_for_different_bytes() {
        assert!(!Mac::verify_magic(b"MAGIC", b"WRONG"));
    }

    #[test]
    fn verify_magic_returns_false_for_different_lengths() {
        assert!(!Mac::verify_magic(b"AB", b"ABCD"));
    }

    #[test]
    fn compute_bytes_returns_raw_array() {
        let data = [b"test".as_slice()];
        let mac_bytes = Mac::compute_bytes(TEST_KEY, &data).unwrap();
        let mac_struct = Mac::compute(TEST_KEY, &data).unwrap();
        assert_eq!(mac_bytes, *mac_struct.as_bytes());
    }
}
