//! Header marshaling and unmarshaling (serialization/deserialization).
//!
//! This module provides functions to convert headers to and from byte streams,
//! handling encoding, MAC computation, and section assembly/disassembly.

use crate::utils::UintType;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::Read;

use super::encoding::{self, EncodedSection, SectionType, SECTION_ORDER};
use super::metadata::{Header, HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use super::verification;

/// Marshals a header into bytes for writing to a file.
///
/// This function:
/// 1. Validates the header and inputs
/// 2. Computes MAC over header components
/// 3. Encodes all sections using Reed-Solomon
/// 4. Assembles the complete header byte stream
///
/// # Arguments
///
/// * `header` - The header to marshal
/// * `salt` - Salt for key derivation
/// * `key` - Encryption key for MAC computation
///
/// # Returns
///
/// Returns the marshaled header as a byte vector.
///
/// # Errors
///
/// Returns an error if:
/// - Header validation fails
/// - Salt length is incorrect
/// - Key is empty
/// - Encoding fails
pub fn marshal(header: &Header, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    validate_inputs(header, salt, key)?;

    let magic = MAGIC_BYTES.to_bytes();
    let header_data = header.serialize_metadata();

    let mac = verification::compute_mac(key, &[&magic, salt, &header_data])?;

    let sections = encode_sections(&magic, salt, &header_data, &mac)?;
    let length_sections = encode_length_prefixes(&sections)?;
    let lengths_header = build_lengths_header(&length_sections);

    Ok(assemble_encoded_header(
        lengths_header,
        length_sections,
        sections,
    ))
}

/// Unmarshals a header from a byte stream.
///
/// This function:
/// 1. Reads length information
/// 2. Decodes all sections
/// 3. Verifies magic bytes
/// 4. Deserializes header metadata
/// 5. Validates the header
///
/// # Arguments
///
/// * `header` - The header to populate
/// * `reader` - Byte stream to read from
///
/// # Errors
///
/// Returns an error if:
/// - Reading fails
/// - Decoding fails
/// - Magic bytes are invalid
/// - Header validation fails
pub fn unmarshal(header: &mut Header, reader: &mut dyn Read) -> Result<()> {
    let length_sizes = read_length_sizes(reader)?;
    let section_lengths = read_and_decode_lengths(reader, &length_sizes)?;
    let decoded_sections = read_and_decode_data(reader, &section_lengths)?;

    header.set_decoded_sections(decoded_sections.clone());

    // Verify magic bytes
    let magic = decoded_sections
        .get(&SectionType::Magic)
        .ok_or_else(|| anyhow!("invalid or missing magic section"))?;

    if magic.len() < MAGIC_SIZE {
        return Err(anyhow!("magic section too short"));
    }

    if !encoding::verify_magic(&magic[..MAGIC_SIZE]) {
        return Err(anyhow!("invalid magic bytes"));
    }

    // Deserialize header data
    let header_data = decoded_sections
        .get(&SectionType::HeaderData)
        .ok_or_else(|| anyhow!("invalid or missing header data section"))?;

    if header_data.len() < HEADER_DATA_SIZE {
        return Err(anyhow!("header data section too short"));
    }

    header.deserialize_metadata(&header_data[..HEADER_DATA_SIZE])?;
    header.validate()?;

    Ok(())
}

// ========== Private Helper Functions ==========

fn validate_inputs(header: &Header, salt: &[u8], key: &[u8]) -> Result<()> {
    header.validate()?;
    if salt.len() != crate::crypto::ARGON_SALT_LEN {
        return Err(anyhow!(
            "invalid salt size: expected {}, got {}",
            crate::crypto::ARGON_SALT_LEN,
            salt.len()
        ));
    }
    if key.is_empty() {
        return Err(anyhow!("key cannot be empty"));
    }
    Ok(())
}

fn encode_sections(
    magic: &[u8],
    salt: &[u8],
    header_data: &[u8],
    mac: &[u8],
) -> Result<HashMap<SectionType, EncodedSection>> {
    let mut sections = HashMap::new();

    sections.insert(SectionType::Magic, encoding::encode_section(magic)?);
    sections.insert(SectionType::Salt, encoding::encode_section(salt)?);
    sections.insert(
        SectionType::HeaderData,
        encoding::encode_section(header_data)?,
    );
    sections.insert(SectionType::MAC, encoding::encode_section(mac)?);

    Ok(sections)
}

fn encode_length_prefixes(
    sections: &HashMap<SectionType, EncodedSection>,
) -> Result<HashMap<SectionType, EncodedSection>> {
    let mut length_sections = HashMap::new();

    for (section_type, section) in sections.iter() {
        length_sections.insert(
            *section_type,
            encoding::encode_length_prefix(section.length)?,
        );
    }

    Ok(length_sections)
}

fn build_lengths_header(length_sections: &HashMap<SectionType, EncodedSection>) -> Vec<u8> {
    let mut lengths_header = Vec::with_capacity(16);

    for section_type in &SECTION_ORDER {
        let sec = length_sections
            .get(section_type)
            .unwrap_or_else(|| panic!("missing encoded length section for {:?}", section_type));
        lengths_header.extend_from_slice(&(sec.data.len() as u32).to_bytes());
    }

    lengths_header
}

fn assemble_encoded_header(
    lengths_header: Vec<u8>,
    length_sections: HashMap<SectionType, EncodedSection>,
    sections: HashMap<SectionType, EncodedSection>,
) -> Vec<u8> {
    let mut result = lengths_header;

    // Append encoded length prefixes
    for section_type in &SECTION_ORDER {
        let sec = length_sections
            .get(section_type)
            .unwrap_or_else(|| panic!("missing encoded length prefix for {:?}", section_type));
        result.extend_from_slice(&sec.data);
    }

    // Append encoded data sections
    for section_type in &SECTION_ORDER {
        let sec = sections
            .get(section_type)
            .unwrap_or_else(|| panic!("missing encoded section for {:?}", section_type));
        result.extend_from_slice(&sec.data);
    }

    result
}

fn read_length_sizes(r: &mut dyn Read) -> Result<HashMap<SectionType, u32>> {
    let mut lengths_header = [0u8; 16];
    r.read_exact(&mut lengths_header)
        .map_err(|e| anyhow!("failed to read lengths header: {}", e))?;

    let mut length_sizes = HashMap::new();
    length_sizes.insert(SectionType::Magic, u32::from_bytes(&lengths_header[0..4]));
    length_sizes.insert(SectionType::Salt, u32::from_bytes(&lengths_header[4..8]));
    length_sizes.insert(
        SectionType::HeaderData,
        u32::from_bytes(&lengths_header[8..12]),
    );
    length_sizes.insert(SectionType::MAC, u32::from_bytes(&lengths_header[12..16]));

    Ok(length_sizes)
}

fn read_and_decode_lengths(
    r: &mut dyn Read,
    length_sizes: &HashMap<SectionType, u32>,
) -> Result<HashMap<SectionType, u32>> {
    let mut section_lengths = HashMap::new();

    for section_type in &SECTION_ORDER {
        let encoded_length = length_sizes
            .get(section_type)
            .ok_or_else(|| anyhow!("missing length size for {:?}", section_type))?;

        let mut encoded_data = vec![0u8; *encoded_length as usize];
        r.read_exact(&mut encoded_data).map_err(|e| {
            anyhow!(
                "failed to read encoded length for {:?}: {}",
                section_type,
                e
            )
        })?;

        let section = EncodedSection {
            data: encoded_data,
            length: 4, // Length prefixes are always 4 bytes original
        };

        let length = encoding::decode_length_prefix(&section)?;
        section_lengths.insert(*section_type, length);
    }

    Ok(section_lengths)
}

fn read_and_decode_data(
    r: &mut dyn Read,
    section_lengths: &HashMap<SectionType, u32>,
) -> Result<HashMap<SectionType, Vec<u8>>> {
    let mut decoded_sections = HashMap::new();

    for section_type in &SECTION_ORDER {
        let length = section_lengths
            .get(section_type)
            .ok_or_else(|| anyhow!("missing section length for {:?}", section_type))?;

        let original_length = *length;
        let encoded_length = encoding::get_encoded_length(original_length as usize);

        let mut encoded_data = vec![0u8; encoded_length];
        r.read_exact(&mut encoded_data)
            .map_err(|e| anyhow!("failed to read encoded {:?}: {}", section_type, e))?;

        let section = EncodedSection {
            data: encoded_data,
            length: original_length,
        };

        let decoded = encoding::decode_section(&section)?;
        decoded_sections.insert(*section_type, decoded);
    }

    Ok(decoded_sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use std::io::Cursor;

    #[test]
    fn test_marshal() {
        let mut header = Header::new().unwrap();
        header.set_original_size(12345);
        header.set_protected(true);

        let salt = crypto::get_random_bytes(crypto::ARGON_SALT_LEN).unwrap();
        let key = vec![0u8; 64];

        let marshalled = marshal(&header, &salt, &key).unwrap();

        // Should have lengths header (16) + encoded sections
        assert!(marshalled.len() > 16);
    }

    #[test]
    fn test_unmarshal() {
        let mut header = Header::new().unwrap();
        header.set_original_size(12345);
        header.set_protected(true);

        let salt = crypto::get_random_bytes(crypto::ARGON_SALT_LEN).unwrap();
        let key = vec![0u8; 64];

        // Marshal
        let marshalled = marshal(&header, &salt, &key).unwrap();

        // Unmarshal
        let mut header2 = Header::new().unwrap();
        let mut cursor = Cursor::new(marshalled);
        unmarshal(&mut header2, &mut cursor).unwrap();

        assert_eq!(header.version, header2.version);
        assert_eq!(header.flags, header2.flags);
        assert_eq!(header.original_size, header2.original_size);
    }
}
