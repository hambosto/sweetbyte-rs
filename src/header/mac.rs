//! HMAC-SHA256 authentication for header integrity.
//!
//! Provides constant-time comparison to prevent timing attacks
//! when verifying header authenticity.
//!
//! # Security Properties
//!
//! - **Authentication**: HMAC-SHA256 ensures the header hasn't been tampered with
//! - **Constant-time comparison**: Uses `subtle::ConstantTimeEq` to prevent timing attacks
//! - **Key separation**: Uses derived key (64 bytes) split between encryption and MAC

use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

/// HMAC-SHA256 calculator and verifier.
///
/// Computes and verifies authentication tags for header integrity.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub struct Mac {
    /// The key for HMAC computation.
    key: Vec<u8>,
}

impl Mac {
    /// Creates a new HMAC calculator with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key for HMAC computation.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty.
    pub fn new(key: &[u8]) -> Result<Self> {
        ensure!(!key.is_empty(), "mac key cannot be empty");
        Ok(Self { key: key.to_vec() })
    }

    /// Computes the HMAC-SHA256 of the given parts.
    ///
    /// HMAC (Hash-based Message Authentication Code) provides:
    /// - **Integrity**: Detects any modification to the data
    /// - **Authentication**: Only someone with the key can compute valid HMAC
    ///
    /// The HMAC computation: HMAC(key, message) = H((key ⊕ opad) || H((key ⊕ ipad) || message))
    ///
    /// # Arguments
    ///
    /// * `parts` - Slices of data to include in the HMAC.
    ///
    /// # Returns
    ///
    /// A 32-byte HMAC digest.
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC creation fails.
    pub fn compute(&self, parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        // Initialize HMAC-SHA256 with the secret key.
        // The hmac crate handles the nested hashing internally.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        // Update HMAC state with all non-empty parts.
        // Empty parts are filtered out to avoid unnecessary operations.
        // This allows passing parts that might be empty without errors.
        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        // Finalize and return as fixed-size array.
        // The result is a 32-byte array (SHA256 output size).
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verifies an HMAC against expected value using constant-time comparison.
    ///
    /// This prevents timing attacks where an attacker could determine
    /// the correct HMAC byte-by-byte by measuring response times.
    ///
    /// Timing attack prevention:
    /// - Standard comparison (==) exits early on first mismatch
    /// - Constant-time comparison compares ALL bytes regardless of position
    /// - This prevents inferring the correct HMAC from timing differences
    ///
    /// # Arguments
    ///
    /// * `expected` - The expected HMAC digest.
    /// * `parts` - The data parts to compute HMAC over.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Expected length is incorrect
    /// - Computed HMAC doesn't match expected
    pub fn verify(&self, expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        // Verify expected length matches MAC_SIZE (32 bytes).
        // This catches truncated/forged HMACs early.
        ensure!(expected.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, expected.len());

        // Compute HMAC of the given parts using the same key.
        // This should produce the same value as the stored HMAC if data is valid.
        let computed = self.compute(parts)?;

        // Convert expected slice to fixed-size array for comparison.
        // This ensures type safety and exact length matching.
        let expected_array: [u8; MAC_SIZE] = expected.try_into().map_err(|_| anyhow!("failed to convert expected mac to array"))?;

        // Constant-time comparison to prevent timing attacks.
        // ct_eq() compares all bytes without early exit, regardless of where
        // the first difference occurs. The result is 0 (false) or 1 (true).
        ensure!(bool::from(expected_array.ct_eq(&computed)), "mac verification failed");

        Ok(())
    }
}
