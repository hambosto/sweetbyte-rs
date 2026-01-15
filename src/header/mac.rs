use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
    if key.is_empty() {
        bail!("key cannot be empty");
    }

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts.iter().filter(|p| !p.is_empty()) {
        mac.update(part);
    }

    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_mac(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
    let computed = compute_mac(key, parts)?;

    if !bool::from(computed.ct_eq(expected)) {
        bail!("MAC verification failed");
    }

    Ok(())
}

pub fn verify_magic(magic: &[u8], expected: &[u8]) -> bool {
    bool::from(magic.ct_eq(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"secret_key";
    const WRONG_KEY: &[u8] = b"wrong_key";

    #[test]
    fn compute_mac_produces_correct_length() {
        let data = [b"Hello".as_slice(), b"World".as_slice()];
        let mac = compute_mac(TEST_KEY, &data).unwrap();
        assert_eq!(mac.len(), MAC_SIZE);
    }

    #[test]
    fn verify_mac_succeeds_with_valid_mac() {
        let data = [b"Hello".as_slice(), b"World".as_slice()];
        let mac = compute_mac(TEST_KEY, &data).unwrap();
        assert!(verify_mac(TEST_KEY, &mac, &data).is_ok());
    }

    #[test]
    fn verify_mac_fails_with_wrong_key() {
        let data = [b"Hello".as_slice()];
        let mac = compute_mac(TEST_KEY, &data).unwrap();
        assert!(verify_mac(WRONG_KEY, &mac, &data).is_err());
    }

    #[test]
    fn verify_mac_fails_with_tampered_mac() {
        let data = [b"Hello".as_slice()];
        let mut mac = compute_mac(TEST_KEY, &data).unwrap();
        mac[0] ^= 0xFF;
        assert!(verify_mac(TEST_KEY, &mac, &data).is_err());
    }

    #[test]
    fn compute_mac_rejects_empty_key() {
        let data = [b"Hello".as_slice()];
        assert!(compute_mac(&[], &data).is_err());
    }

    #[test]
    fn compute_mac_handles_empty_parts() {
        let data = [b"Hello".as_slice(), b"".as_slice(), b"World".as_slice()];
        let mac = compute_mac(TEST_KEY, &data).unwrap();
        let data_no_empty = [b"Hello".as_slice(), b"World".as_slice()];
        let mac_no_empty = compute_mac(TEST_KEY, &data_no_empty).unwrap();

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
}
