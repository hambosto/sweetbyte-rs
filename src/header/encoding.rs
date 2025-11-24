//! Header section encoding using Reed-Solomon error correction.
//!
//! This module handles encoding and decoding of header sections with
//! Reed-Solomon error correction for resilience.

use crate::encoding::ErasureEncoder;
use crate::utils::UintType;
use anyhow::{Result, anyhow};

/// Section types in the encrypted file header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    /// Magic bytes for file identification
    Magic,
    /// Salt for key derivation
    Salt,
    /// Header metadata (version, flags, size)
    HeaderData,
    /// Message Authentication Code
    MAC,
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionType::Magic => write!(f, "magic"),
            SectionType::Salt => write!(f, "salt"),
            SectionType::HeaderData => write!(f, "header_data"),
            SectionType::MAC => write!(f, "mac"),
        }
    }
}

/// Order in which sections appear in the encoded header
pub const SECTION_ORDER: [SectionType; 4] = [
    SectionType::Magic,
    SectionType::Salt,
    SectionType::HeaderData,
    SectionType::MAC,
];

/// An encoded section with its data and length
pub struct EncodedSection {
    /// Encoded data bytes
    pub data: Vec<u8>,
    /// Length of the encoded data
    pub length: u32,
}

/// Encodes a section using Reed-Solomon encoding.
///
/// # Arguments
///
/// * `data` - The raw section data to encode
///
/// # Returns
///
/// Returns an `EncodedSection` with the encoded data and its length.
///
/// # Errors
///
/// Returns an error if:
/// - Data is empty
/// - Encoding fails
/// - Encoded length exceeds u32::MAX
pub fn encode_section(data: &[u8]) -> Result<EncodedSection> {
    if data.is_empty() {
        return Err(anyhow!("data cannot be empty"));
    }

    let encoder =
        ErasureEncoder::new(crate::encoding::DATA_SHARDS, crate::encoding::PARITY_SHARDS)?;
    let encoded = encoder.encode(data)?;
    let original_len = data.len();

    if original_len > u32::MAX as usize {
        return Err(anyhow!(
            "original data length {} exceeds maximum allowed size for u32",
            original_len
        ));
    }

    Ok(EncodedSection {
        data: encoded,
        length: original_len as u32,
    })
}

/// Decodes a section using Reed-Solomon decoding.
///
/// # Arguments
///
/// * `section` - The encoded section to decode
///
/// # Returns
///
/// Returns the decoded data bytes.
///
/// # Errors
///
/// Returns an error if:
/// - Section data is empty
/// - Decoding fails
pub fn decode_section(section: &EncodedSection) -> Result<Vec<u8>> {
    if section.data.is_empty() {
        return Err(anyhow!("invalid encoded section"));
    }

    let encoder =
        ErasureEncoder::new(crate::encoding::DATA_SHARDS, crate::encoding::PARITY_SHARDS)?;
    let decoded = encoder.decode(&section.data)?;

    // Truncate to original length if needed (padding removal)
    let original_len = section.length as usize;
    if decoded.len() < original_len {
        return Err(anyhow!("decoded data shorter than expected length"));
    }

    Ok(decoded[..original_len].to_vec())
}

/// Encodes a length value as a section.
///
/// This is used to encode the lengths of other sections so they can
/// be stored with error correction.
///
/// # Arguments
///
/// * `length` - The length value to encode
///
/// # Returns
///
/// Returns an `EncodedSection` containing the encoded length.
pub fn encode_length_prefix(length: u32) -> Result<EncodedSection> {
    let length_bytes = length.to_bytes();
    encode_section(&length_bytes)
}

/// Decodes a length value from a section.
///
/// # Arguments
///
/// * `section` - The encoded section containing a length value
///
/// # Returns
///
/// Returns the decoded length as u32.
///
/// # Errors
///
/// Returns an error if:
/// - Decoding fails
/// - Decoded data is less than 4 bytes
pub fn decode_length_prefix(section: &EncodedSection) -> Result<u32> {
    let decoded = decode_section(section)?;

    if decoded.len() < 4 {
        return Err(anyhow!("invalid length prefix size"));
    }

    Ok(u32::from_bytes(&decoded[..4]))
}

/// Verifies that magic bytes match the expected value.
///
/// # Arguments
///
/// * `magic` - The magic bytes to verify
///
/// # Returns
///
/// Returns `true` if magic bytes are valid, `false` otherwise.
pub fn verify_magic(magic: &[u8]) -> bool {
    if magic.len() < 4 {
        return false;
    }
    let expected = crate::header::MAGIC_BYTES.to_bytes();
    magic[..4] == expected[..]
}

/// Calculates the encoded length for a given original data length.
///
/// # Arguments
/// * `original_len` - Length of the original data
///
/// # Returns
/// Length of the data after encoding
pub fn get_encoded_length(original_len: usize) -> usize {
    let shard_size = original_len.div_ceil(crate::encoding::DATA_SHARDS);
    shard_size * (crate::encoding::DATA_SHARDS + crate::encoding::PARITY_SHARDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_encode_decode() {
        let data = b"test data";

        let encoded = encode_section(data).unwrap();
        let decoded = decode_section(&encoded).unwrap();

        // Reed-Solomon encoding may add padding
        assert!(decoded.len() >= data.len());
        assert_eq!(data.as_slice(), &decoded[..data.len()]);
    }

    #[test]
    fn test_verify_magic() {
        let magic = 0xCAFEBABEu32.to_bytes();
        assert!(verify_magic(&magic));

        let wrong = vec![0u8; 4];
        assert!(!verify_magic(&wrong));
    }
}
