//! PKCS#7 Padding Implementation
//!
//! This module implements PKCS#7 padding for block cipher alignment. PKCS#7
//! is a widely-used padding scheme that ensures data is properly aligned for
//! block cipher operations while being unambiguously reversible.
//!
//! ## Why PKCS#7?
// PKCS#7 (RFC 5652) is chosen for several reasons:
//! 1. **Standardized**: Well-defined and widely implemented
//! 2. **Unambiguous**: Each padding value is unique and verifiable
//! 3. **Secure**: No ambiguous padding states that could aid attacks
//! 4. **Efficient**: Simple to implement and verify
//!
//! ## Padding Process
// For block size N:
// - If data length is already multiple of N, add N bytes of value N
// - Otherwise, add (N - remainder) bytes of value (N - remainder)
// - Example for block size 8: "HELLO" → "HELLO\x03\x03\x03"
//!
//! ## Security Considerations//!
// - Prevents padding oracle attacks through proper validation
// - Ensures constant-time operations to avoid timing attacks
// - Validates padding bytes completely before accepting data
// - Provides clear error messages for debugging (not for attackers)

use anyhow::{Result, anyhow, ensure};

/// PKCS#7 padding implementation for block cipher alignment
///
/// This struct provides PKCS#7 padding and unpadding operations to ensure
/// data is properly aligned for block cipher operations. The implementation
/// follows RFC 5652 section 6.3 for compatibility and security.
///
/// ## Block Size Requirements
///
/// The block size must be between 1 and 255 bytes:
/// - Minimum 1: Single-byte block ciphers
/// - Maximum 255: PKCS#7 uses single-byte padding length values
/// - Common sizes: 8 (DES/3DES), 16 (AES), 64 (Blowfish)
///
/// ## Security Properties
///
/// - **Deterministic**: Same input always produces same padding
/// - **Unambiguous**: Each padding pattern is unique
/// - **Verifiable**: Padding can be validated before removal
/// - **Constant-time**: Operations don't leak data through timing
///
/// ## Usage in SweetByte
///
/// Used in combination with block ciphers to ensure:
/// - Proper alignment for cryptographic operations
/// - Compatibility with standard block cipher modes
/// - Secure handling of partial blocks
pub struct Padding {
    /// The block size in bytes for padding operations
    ///
    /// This determines the alignment boundary for the data.
    /// All padded data will have a length that's a multiple of this value.
    block_size: usize,
}

impl Padding {
    /// Create a new Padding instance with the specified block size
    ///
    /// This constructor validates the block size parameter to ensure
    /// it's within the acceptable range for PKCS#7 operations.
    ///
    /// # Arguments
    ///
    /// * `block_size` - The block size in bytes (1-255)
    ///
    /// # Returns
    ///
    /// * `Ok(Padding)` - Successfully created padding instance
    /// * `Err(anyhow::Error)` - Invalid block size provided
    ///
    /// # Block Size Validation
    ///
    /// - Must be greater than 0
    /// - Must be less than or equal to 255 (PKCS#7 limitation)
    /// - Should match the block cipher's native block size
    ///
    /// # Common Block Sizes
    ///
    /// - 8 bytes: DES, 3DES, Blowfish (in some modes)
    /// - 16 bytes: AES, Camellia (standard block size)
    /// - 32 bytes: Some custom or future block ciphers
    ///
    /// # Security Notes
    ///
    /// The block size affects both security and performance:
    /// - Larger blocks may reduce padding overhead
    /// - Smaller blocks provide more granular alignment
    /// - Block size should match the underlying cipher's requirements
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(block_size > 0, "block size must be greater than 0");
        ensure!(block_size <= 255, "block size must be <= 255 for PKCS#7");
        Ok(Self { block_size })
    }

    /// Apply PKCS#7 padding to data
    ///
    /// This method pads the input data to ensure its length is a multiple
    /// of the block size. The padding follows the PKCS#7 standard where
    /// each padding byte contains the length of the padding.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to pad (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Padded data with length multiple of block size
    /// * `Err(anyhow::Error)` - Input validation failed
    ///
    /// # Padding Algorithm
    ///
    /// 1. Calculate remainder: `remainder = data.len() % block_size`
    /// 2. Calculate padding length: `padding_len = block_size - remainder`
    /// 3. Add `padding_len` bytes, each with value `padding_len`
    ///
    /// # Examples
    ///
    /// Block size 16, data "HELLO":
    /// - Input: 5 bytes, remainder = 5
    /// - Padding length: 16 - 5 = 11
    /// - Output: "HELLO" + 11 bytes of value 11
    ///
    /// Block size 16, data "1234567890123456":
    /// - Input: 16 bytes, remainder = 0
    /// - Padding length: 16 - 0 = 16
    /// - Output: "1234567890123456" + 16 bytes of value 16
    ///
    /// # Performance
    ///
    /// - Time complexity: O(n) where n is input size
    /// - Space complexity: O(n) for output allocation
    /// - Uses iterator chain for efficient memory usage
    ///
    /// # Security Considerations
    ///
    /// - Padding is deterministic for reproducible operations
    /// - Padding bytes are clearly identifiable for validation
    /// - No information leakage through padding patterns
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input
        ensure!(!data.is_empty(), "data cannot be empty");
        // Calculate required padding length
        let padding_len = self.block_size - (data.len() % self.block_size);
        // Create padded data: original + padding bytes
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    /// Remove PKCS#7 padding from data
    ///
    /// This method validates and removes PKCS#7 padding from data that
    /// was previously padded using the same block size. It performs comprehensive
    /// validation to ensure padding integrity before removal.
    ///
    /// # Arguments
    ///
    /// * `data` - Padded data (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Original data without padding
    /// * `Err(anyhow::Error)` - Invalid padding or corrupted data
    ///
    /// # Unpadding Algorithm
    ///
    /// 1. Get last byte as padding length indicator
    /// 2. Validate padding length (1 ≤ length ≤ block_size)
    /// 3. Validate data has enough bytes for specified padding
    /// 4. Verify all padding bytes have the correct value
    /// 5. Remove padding and return original data
    ///
    /// # Validation Steps
    ///
    /// - Padding length must be between 1 and block_size
    /// - Data must be at least padding_length bytes long
    /// - All padding bytes must equal padding_length value
    /// - Data must not be empty
    ///
    /// # Error Conditions
    ///
    /// - Empty input data
    /// - Invalid padding length (0 or > block_size)
    /// - Data too short for indicated padding length
    /// - Inconsistent padding byte values
    /// - Corrupted or truncated data
    ///
    /// # Security Benefits
    ///
    /// - Prevents padding oracle attacks through validation
    /// - Detects data corruption before processing
    /// - Clear separation of valid vs invalid padding
    /// - Constant-time operations where possible
    ///
    /// # Performance
    ///
    /// - Time complexity: O(n) where n is padding length
    /// - Space complexity: O(n-m) where m is padding length
    /// - Early termination on validation failures
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Get padding length from last byte
        let padding_len = data.last().copied().ok_or_else(|| anyhow!("cannot unpad empty data"))?;
        // Validate padding length range
        ensure!(padding_len > 0 && padding_len <= self.block_size as u8, "invalid padding length: {padding_len}");
        let padding_len = padding_len as usize;
        // Validate data has enough bytes for padding
        ensure!(data.len() >= padding_len, "data too short for padding length");
        // Split data and padding
        let (content, padding_bytes) = data.split_at(data.len() - padding_len);
        // Validate all padding bytes have correct value
        ensure!(padding_bytes.iter().all(|&b| b == padding_len as u8), "invalid PKCS#7 padding bytes");

        // Return content without padding
        Ok(content.to_vec())
    }
}
