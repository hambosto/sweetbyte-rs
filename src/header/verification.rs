//! Header verification and MAC (Message Authentication Code) operations.
//!
//! This module provides functions for computing and verifying MACs using HMAC-SHA256,
//! and for verifying the integrity and authenticity of file headers.

use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::encoding::SectionType;
use super::metadata::{HEADER_DATA_SIZE, Header, MAC_SIZE, MAGIC_SIZE};

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 MAC over multiple data parts.
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `parts` - Slices of data to authenticate (will be concatenated)
///
/// # Returns
///
/// Returns the computed MAC as a 32-byte vector.
pub fn compute_mac(key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("key cannot be empty"));
    }

    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("failed to create HMAC: {}", e))?;

    for part in parts {
        if !part.is_empty() {
            mac.update(part);
        }
    }

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verifies a MAC using constant-time comparison.
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `expected_mac` - The expected MAC value
/// * `parts` - Slices of data that were authenticated
///
/// # Returns
///
/// Returns `Ok(())` if the MAC is valid, error otherwise.
///
/// # Errors
///
/// Returns an error if:
/// - Key is empty
/// - MAC computation fails
/// - MAC verification fails
pub fn verify_mac(key: &[u8], expected_mac: &[u8], parts: &[&[u8]]) -> Result<()> {
    let computed_mac = compute_mac(key, parts)?;

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    if computed_mac.ct_eq(expected_mac).into() {
        Ok(())
    } else {
        Err(anyhow!("MAC verification failed"))
    }
}

/// Verifies the integrity and authenticity of a header.
///
/// This function performs complete header verification by:
/// 1. Extracting the MAC and header sections
/// 2. Computing expected MAC over header components
/// 3. Comparing computed MAC with stored MAC using constant-time comparison
///
/// # Arguments
///
/// * `header` - The header to verify
/// * `key` - The encryption key
///
/// # Returns
///
/// Returns `Ok(())` if verification succeeds, error otherwise.
///
/// # Errors
///
/// Returns an error if:
/// - Key is empty
/// - Required sections are missing
/// - MAC verification fails
pub fn verify_header(header: &Header, key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(anyhow!("key cannot be empty"));
    }

    let expected_mac = header.section(SectionType::MAC, MAC_SIZE)?;
    let magic = header.section(SectionType::Magic, MAGIC_SIZE)?;
    let salt = header.section(SectionType::Salt, crate::crypto::ARGON_SALT_LEN)?;
    let header_data = header.section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

    verify_mac(key, &expected_mac, &[&magic, &salt, &header_data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_verify_mac() {
        let key = b"test_key";
        let parts = vec![b"part1".as_slice(), b"part2".as_slice()];

        let mac = compute_mac(key, &parts).unwrap();
        assert!(verify_mac(key, &mac, &parts).is_ok());

        // Wrong MAC should fail
        let wrong_mac = vec![0u8; 32];
        assert!(verify_mac(key, &wrong_mac, &parts).is_err());
    }
}
