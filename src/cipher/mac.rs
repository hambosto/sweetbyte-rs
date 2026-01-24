//! # HMAC-SHA256 Message Authentication
//!
//! This module provides HMAC (Hash-based Message Authentication Code) using SHA-256
//! for cryptographic authentication of data. HMAC combines cryptographic hash functions
//! with secret keys to provide both data integrity and authenticity.
//!
//! ## Security Properties
//!
//! - **Authenticity**: Only someone with the secret key can generate valid MACs
//! - **Integrity**: Any modification to authenticated data will be detected
// - **Collision Resistance**: Based on SHA-256's collision resistance
// - **Key Separation**: Inner and outer hash layers prevent key recovery attacks
//!
//! ## Use Cases
//!
//! - Authenticating encrypted file headers
//! - Verifying the integrity of configuration metadata
//! - Protecting against tampering in storage/transmission
//! - Providing cryptographic guarantees beyond mere hashing
//!
//! ## Threat Model
//!
// Protects against: data tampering, forgery attempts, replay attacks (with sequence numbers)

use anyhow::{Result, anyhow, ensure};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::MAC_SIZE;

/// # HMAC-SHA256 Authentication
///
/// Provides message authentication using HMAC with SHA-256 as the underlying hash.
/// Suitable for authenticating arbitrary data including file headers, metadata,
/// and other sensitive information that requires integrity and authenticity guarantees.
///
/// The MAC output is 32 bytes (256 bits) providing strong security against
/// forgery attempts while maintaining reasonable performance.
///
/// ## Security Considerations
///
/// - Uses cryptographically secure HMAC construction
/// - Constant-time verification prevents timing attacks
/// - Key should be kept secret and properly protected
/// - Different keys should be used for different purposes
/// - HMAC keys should be randomly generated and sufficiently long
pub struct Mac {
    /// Secret key for HMAC computation
    /// Stored as `Vec<u8>` to support variable-length keys
    /// Recommended minimum length: 32 bytes (256 bits)
    key: Vec<u8>,
}

impl Mac {
    /// Creates a new MAC instance with the provided secret key
    ///
    /// # Arguments
    /// * `key` - Secret key for HMAC computation, must not be empty
    ///
    /// # Returns
    /// Configured MAC instance ready for authentication operations
    ///
    /// # Errors
    /// Returns error if the key is empty
    ///
    /// # Security Notes
    /// - The key is copied into the struct for repeated use
    /// - Key length should be at least 32 bytes for optimal security
    /// - Keys should be generated using cryptographically secure randomness
    /// - Different applications should use different keys (key separation)
    /// - Consider using a secure allocator for sensitive key material
    pub fn new(key: &[u8]) -> Result<Self> {
        // Validate input to prevent empty key usage
        ensure!(!key.is_empty(), "mac key cannot be empty");
        Ok(Self { key: key.to_vec() })
    }

    /// Computes HMAC-SHA256 of multiple data parts
    ///
    /// Computes HMAC over the concatenation of multiple data parts without
    /// actually concatenating them in memory. This is efficient for authenticating
    /// structured data like file headers with multiple fields.
    ///
    /// # Arguments
    /// * `parts` - Data parts to authenticate, empty parts are automatically filtered out
    ///
    /// # Returns
    /// 32-byte HMAC tag authenticating the provided data
    ///
    /// # Errors
    /// Returns error if:
    /// - HMAC initialization fails (should never happen with valid key)
    /// - Key is empty (prevented by constructor validation)
    ///
    /// # Security Guarantees
    /// - Authenticates all provided data parts in order
    /// - MAC is cryptographically bound to the secret key
    /// - Empty parts are ignored to prevent accidental MAC changes
    /// - Suitable for authenticating structured data with variable fields
    ///
    /// # Performance Characteristics
    /// - O(total_data_size) complexity
    /// - SHA-256 operations optimized for modern CPUs
    /// - No memory allocation for data concatenation
    /// - Constant-time operations for sensitive operations
    ///
    /// # Use Cases
    /// - Authenticating file headers with multiple sections
    /// - Verifying metadata integrity
    /// - Creating tamper-evident logs or records
    /// - Multi-part message authentication
    pub fn compute(&self, parts: &[&[u8]]) -> Result<[u8; MAC_SIZE]> {
        // Initialize HMAC with SHA-256 and the secret key
        // Hmac::new_from_slice validates key length and sets up the HMAC state
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|e| anyhow!("hmac creation failed: {e}"))?;

        // Update HMAC with each non-empty data part
        // This authenticates the data without requiring memory concatenation
        parts
            .iter()
            .filter(|part| !part.is_empty()) // Skip empty parts to maintain consistency
            .for_each(|part| mac.update(part));

        // Finalize HMAC computation and extract the 32-byte tag
        // finalize() consumes the MAC instance and returns the result
        // into_bytes() provides access to the raw MAC bytes
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verifies HMAC against expected value
    ///
    /// Performs constant-time verification of HMAC to prevent timing attacks.
    /// Computes the HMAC of the provided data and compares it with the expected value.
    ///
    /// # Arguments
    /// * `expected` - Expected HMAC tag (32 bytes)
    /// * `parts` - Data parts that were originally authenticated
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, Err() if verification fails
    ///
    /// # Errors
    /// Returns error if:
    /// - Expected MAC length is invalid (not 32 bytes)
    /// - Expected MAC cannot be converted to array (shouldn't happen with correct length)
    /// - Computed MAC doesn't match expected MAC (authentication failure)
    ///
    /// # Security Guarantees
    /// - Constant-time comparison prevents timing attacks
    /// - Authentication failure provides no information about the data
    /// - Protects against forgery attempts without the secret key
    /// - Detects any modification to authenticated data
    ///
    /// # Performance
    /// - O(total_data_size) for HMAC computation
    /// - O(1) for constant-time comparison (32 bytes)
    /// - No early exit on MAC mismatch to prevent timing attacks
    ///
    /// # Security Notes
    /// - Always performs the full comparison to prevent timing attacks
    /// - A verification failure indicates either data tampering or wrong key
    /// - Never returns detailed error information that could aid attackers
    /// - Suitable for verifying data integrity after storage or transmission
    pub fn verify(&self, expected: &[u8], parts: &[&[u8]]) -> Result<()> {
        // Validate expected MAC length (must be exactly 32 bytes)
        ensure!(expected.len() == MAC_SIZE, "invalid mac length: expected {}, got {}", MAC_SIZE, expected.len());

        // Compute HMAC of the provided data parts
        let computed = self.compute(parts)?;
        // Convert expected MAC to fixed-size array for comparison
        // This also validates that the expected MAC has correct length
        let expected_array: [u8; MAC_SIZE] = expected.try_into().map_err(|_| anyhow!("failed to convert expected mac to array"))?;

        // Perform constant-time comparison to prevent timing attacks
        // ct_eq() returns a Choice type that prevents early exit
        ensure!(bool::from(expected_array.ct_eq(&computed)), "mac verification failed");

        Ok(())
    }
}
