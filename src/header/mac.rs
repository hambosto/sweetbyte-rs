use anyhow::{Result, bail};
use hmac::{Hmac, Mac as HmacMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mac(pub [u8; MAC_SIZE]);

impl Mac {
    pub fn compute(key: &[u8], parts: &[&[u8]]) -> Result<Self> {
        if key.is_empty() {
            bail!("key cannot be empty");
        }

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        for part in parts.iter().filter(|p| !p.is_empty()) {
            mac.update(part);
        }

        Ok(Self(mac.finalize().into_bytes().into()))
    }

    pub fn verify(&self, key: &[u8], parts: &[&[u8]]) -> Result<()> {
        let computed = Self::compute(key, parts)?;

        if !bool::from(computed.0.ct_eq(&self.0)) {
            bail!("MAC verification failed");
        }

        Ok(())
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MAC_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Mac {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; MAC_SIZE]> for Mac {
    #[inline]
    fn from(bytes: [u8; MAC_SIZE]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mac([{} bytes])", MAC_SIZE)
    }
}

#[inline]
pub fn compute_mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
    Ok(*Mac::compute(key, parts)?.as_bytes())
}

#[inline]
pub fn verify_mac(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
    if expected.len() != MAC_SIZE {
        bail!("invalid MAC length: expected {}, got {}", MAC_SIZE, expected.len());
    }

    let expected_array: [u8; MAC_SIZE] = expected.try_into().expect("length verified");
    Mac(expected_array).verify(key, parts)
}

#[inline]
#[must_use]
pub fn verify_magic(magic: &[u8], expected: &[u8]) -> bool {
    bool::from(magic.ct_eq(expected))
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
    fn compute_mac_handles_empty_parts() {
        let data = [b"Hello".as_slice(), b"".as_slice(), b"World".as_slice()];
        let mac = Mac::compute(TEST_KEY, &data).unwrap();
        let data_no_empty = [b"Hello".as_slice(), b"World".as_slice()];
        let mac_no_empty = Mac::compute(TEST_KEY, &data_no_empty).unwrap();

        assert_eq!(mac, mac_no_empty);
    }

    #[test]
    fn verify_magic_returns_true_for_matching_bytes() {
        assert!(verify_magic(b"MAGIC", b"MAGIC"));
    }

    #[test]
    fn verify_magic_returns_false_for_different_bytes() {
        assert!(!verify_magic(b"MAGIC", b"WRONG"));
    }

    #[test]
    fn verify_magic_returns_false_for_different_lengths() {
        assert!(!verify_magic(b"AB", b"ABCD"));
    }

    #[test]
    fn mac_debug_does_not_leak_bytes() {
        let mac = Mac([0u8; MAC_SIZE]);
        let debug_str = format!("{:?}", mac);
        assert!(debug_str.contains("Mac"));
        assert!(!debug_str.contains("0, 0, 0"));
    }
}
