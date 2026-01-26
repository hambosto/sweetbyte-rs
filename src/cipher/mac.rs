//! Message Authentication Code (MAC) implementation.
//!
//! This module provides HMAC-SHA256 functionality to ensure the integrity and authenticity
//! of the file header.
//!
//! # Purpose
//!
//! While the file *body* is protected by the AEAD (AES-GCM or XChaCha20-Poly1305),
//! the *header* (containing metadata, salt, and parameters) needs independent verification
//! before we can even derive the keys to decrypt the body. We use HMAC-SHA256 for this purpose.
//!
//! # Security
//!
//! - **Algorithm**: HMAC-SHA256
//! - **Key**: Derived specifically for the MAC (separate from encryption keys)
//! - **Verification**: Constant-time comparison to prevent timing attacks

use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

/// A context for computing and verifying HMAC-SHA256 tags.
pub struct Mac {
    /// The secret key used for HMAC generation.
    key: Vec<u8>,
}

impl Mac {
    /// Initializes a new MAC context with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty.
    pub fn new(key: &[u8]) -> Result<Self> {
        // Enforce non-empty key.
        ensure!(!key.is_empty(), "mac key cannot be empty");
        Ok(Self { key: key.to_vec() })
    }

    /// Computes the HMAC tag for a list of data parts.
    ///
    /// This method allows feeding multiple disjoint parts (e.g., salt + metadata)
    /// without needing to concatenate them into a single buffer first.
    ///
    /// # Returns
    ///
    /// Returns the 32-byte HMAC-SHA256 tag.
    pub fn compute(&self, parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        // Initialize HMAC-SHA256 with the stored key.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        // Update the HMAC state with each non-empty part.
        // We filter empty parts to avoid unnecessary calls, though they wouldn't affect the hash.
        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        // Finalize and return the fixed-size array.
        // into_bytes() gives GenericArray, into() converts to [u8; 32].
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verifies that the computed MAC for the data matches the expected tag.
    ///
    /// # Security
    ///
    /// This method uses **constant-time comparison** to prevent timing attacks.
    /// This is critical because if an attacker can determine how many bytes of the
    /// MAC matched, they could forge a valid header.
    pub fn verify(&self, expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        // Basic length check.
        ensure!(expected.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, expected.len());

        // Compute the actual MAC for the provided data parts.
        let computed = self.compute(parts)?;

        // Convert the expected slice to a fixed-size array for comparison.
        let expected_array: [u8; MAC_SIZE] = expected.try_into().map_err(|_| anyhow!("failed to convert expected mac to array"))?;

        // Perform constant-time equality check.
        // ct_eq ensures the time taken is independent of the number of matching bytes.
        ensure!(bool::from(expected_array.ct_eq(&computed)), "mac verification failed");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_new_valid() {
        let key = b"secret key";
        let mac = Mac::new(key);
        assert!(mac.is_ok());
    }

    #[test]
    fn test_mac_new_empty() {
        assert!(Mac::new(&[]).is_err());
    }

    #[test]
    fn test_compute_verify_roundtrip() {
        let key = b"secret key";
        let mac = Mac::new(key).unwrap();
        let part1 = b"header";
        let part2 = b"data";

        let tag = mac.compute(&[part1, part2]).unwrap();
        assert_eq!(tag.len(), MAC_SIZE);

        assert!(mac.verify(&tag, &[part1, part2]).is_ok());
    }

    #[test]
    fn test_verify_invalid_tag() {
        let key = b"secret key";
        let mac = Mac::new(key).unwrap();
        let part1 = b"data";

        let tag = mac.compute(&[part1]).unwrap();
        let mut invalid_tag = tag;
        invalid_tag[0] ^= 0x01; // Flip a bit

        assert!(mac.verify(&invalid_tag, &[part1]).is_err());
    }

    #[test]
    fn test_verify_different_data() {
        let key = b"secret key";
        let mac = Mac::new(key).unwrap();
        let part1 = b"data";

        let tag = mac.compute(&[part1]).unwrap();

        // Verification should fail if data changes
        assert!(mac.verify(&tag, &[b"different data"]).is_err());
    }

    #[test]
    fn test_compute_empty_parts() {
        let key = b"secret key";
        let mac = Mac::new(key).unwrap();

        // Ensure empty parts don't change the hash
        let tag1 = mac.compute(&[b"data"]).unwrap();
        let tag2 = mac.compute(&[b"data", b""]).unwrap();
        assert_eq!(tag1, tag2);
    }
}
