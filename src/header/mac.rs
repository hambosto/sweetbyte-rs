use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as HmacMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 message authentication code holder.
///
/// Provides constant-time verification for integrity checking of header data.
#[derive(Debug, Clone)]
pub struct Mac([u8; MAC_SIZE]);

impl Mac {
    /// Creates a Mac from raw bytes.
    ///
    /// # Arguments
    /// * `bytes` - The 32-byte MAC value.
    ///
    /// # Returns
    /// A new Mac instance.
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; MAC_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the MAC as a byte slice.
    ///
    /// # Returns
    /// Reference to the 32-byte MAC.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MAC_SIZE] {
        &self.0
    }

    /// Computes HMAC-SHA256 over multiple data parts.
    ///
    /// The parts are concatenated in order before MAC computation.
    ///
    /// # Arguments
    /// * `key` - The secret key for HMAC.
    /// * `parts` - Array of data parts to MAC.
    ///
    /// # Returns
    /// The computed Mac on success, or an error.
    pub fn compute(key: &[u8], parts: &[&[u8]]) -> Result<Self> {
        ensure!(!key.is_empty(), "mac key cannot be empty");

        // Initialize HMAC with the key.
        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        // Update with each non-empty part.
        parts.iter().filter(|part| !part.is_empty()).for_each(|part| mac.update(part));

        Ok(Self(mac.finalize().into_bytes().into()))
    }

    /// Computes HMAC-SHA256 and returns raw bytes.
    ///
    /// # Arguments
    /// * `key` - The secret key for HMAC.
    /// * `parts` - Array of data parts to MAC.
    ///
    /// # Returns
    /// The 32-byte MAC on success, or an error.
    #[inline]
    pub fn compute_bytes(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        Self::compute(key, parts).map(|mac| mac.0)
    }

    /// Verifies the MAC using constant-time comparison.
    ///
    /// Uses subtle::ConstantTimeEq to prevent timing attacks.
    ///
    /// # Arguments
    /// * `key` - The secret key for HMAC.
    /// * `parts` - Array of data parts that were MAC'd.
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, or an error if it fails.
    pub fn verify(&self, key: &[u8], parts: &[&[u8]]) -> Result<()> {
        // Compute the expected MAC.
        let computed = Self::compute(key, parts)?;

        // Perform constant-time comparison.
        ensure!(bool::from(self.0.ct_eq(&computed.0)), "mac verification failed");

        Ok(())
    }

    /// Verifies raw bytes as a MAC.
    ///
    /// # Arguments
    /// * `key` - The secret key for HMAC.
    /// * `expected` - The expected MAC bytes.
    /// * `parts` - Array of data parts that were MAC'd.
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, or an error if it fails.
    pub fn verify_bytes(key: &[u8], expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        let mac = Self::try_from(expected)?;
        mac.verify(key, parts)
    }
}

impl AsRef<[u8]> for Mac {
    /// Returns the MAC as a byte slice reference.
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Mac> for [u8; MAC_SIZE] {
    /// Converts a Mac into its raw byte representation.
    #[inline]
    fn from(mac: Mac) -> Self {
        mac.0
    }
}

impl TryFrom<&[u8]> for Mac {
    type Error = anyhow::Error;

    /// Attempts to create a Mac from a byte slice.
    ///
    /// # Arguments
    /// * `value` - The byte slice to convert (must be exactly MAC_SIZE bytes).
    ///
    /// # Returns
    /// A Mac instance on success, or an error if the slice length is wrong.
    fn try_from(value: &[u8]) -> Result<Self> {
        ensure!(value.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, value.len());

        let array: [u8; MAC_SIZE] = value.try_into().map_err(|_| anyhow!("mac conversion failed"))?;
        Ok(Self::from_bytes(array))
    }
}
