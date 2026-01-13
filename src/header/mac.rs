//! HMAC-SHA256 for header authentication.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::MAC_SIZE;

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 over the given parts.
///
/// # Arguments
/// * `key` - The HMAC key
/// * `parts` - The data parts to authenticate
///
/// # Returns
/// The 32-byte MAC
pub fn compute_mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
    if key.is_empty() {
        bail!("key cannot be empty");
    }

    let mut mac = HmacSha256::new_from_slice(key).context("HMAC initialization failed")?;

    for part in parts {
        if !part.is_empty() {
            mac.update(part);
        }
    }

    let result = mac.finalize();
    let bytes: [u8; MAC_SIZE] = result.into_bytes().into();

    Ok(bytes)
}

/// Verifies HMAC-SHA256 against an expected value.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
/// * `key` - The HMAC key
/// * `expected` - The expected MAC value
/// * `parts` - The data parts to verify
pub fn verify_mac(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
    let computed = compute_mac(key, parts)?;

    // Constant-time comparison
    if !constant_time_eq(&computed, expected) {
        bail!("MAC verification failed");
    }

    Ok(())
}

/// Constant-time equality comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Verifies magic bytes against the expected value.
///
/// # Arguments
/// * `magic` - The magic bytes to verify
/// * `expected` - The expected magic value as bytes
pub fn verify_magic(magic: &[u8], expected: &[u8]) -> bool {
    magic == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_mac() {
        let key = b"secret_key";
        let data = [b"Hello".as_slice(), b"World".as_slice()];

        let mac = compute_mac(key, &data).unwrap();
        assert_eq!(mac.len(), MAC_SIZE);
    }

    #[test]
    fn test_verify_mac() {
        let key = b"secret_key";
        let data = [b"Hello".as_slice(), b"World".as_slice()];

        let mac = compute_mac(key, &data).unwrap();
        assert!(verify_mac(key, &mac, &data).is_ok());
    }

    #[test]
    fn test_verify_mac_wrong_key() {
        let key = b"secret_key";
        let wrong_key = b"wrong_key";
        let data = [b"Hello".as_slice()];

        let mac = compute_mac(key, &data).unwrap();
        assert!(verify_mac(wrong_key, &mac, &data).is_err());
    }

    #[test]
    fn test_verify_mac_tampered() {
        let key = b"secret_key";
        let data = [b"Hello".as_slice()];

        let mut mac = compute_mac(key, &data).unwrap();
        mac[0] ^= 0xFF; // Tamper with MAC

        assert!(verify_mac(key, &mac, &data).is_err());
    }

    #[test]
    fn test_compute_mac_empty_key() {
        let data = [b"Hello".as_slice()];
        assert!(compute_mac(&[], &data).is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
