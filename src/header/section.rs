//! Low-level header section management with error correction.
//!
//! This module handles the physical layout of the header components. It implements
//! the "Shield" mechanism, which protects critical header data (magic bytes, salt,
//! metadata, MAC) using Reed-Solomon erasure coding.
//!
//! # Layout
//!
//! The header is stored as a sequence of lengths followed by the encoded data sections:
//!
//! 1. **Lengths Header**: A fixed-size block containing the length of each encoded section.
//! 2. **Encoded Sections**: The variable-length encoded byte arrays for:
//!    - Magic Bytes
//!    - Salt
//!    - Header Data (Parameters)
//!    - Metadata
//!    - MAC
//!
//! Each section is independently Reed-Solomon encoded, allowing the header to be recovered
//! even if parts of it are corrupted.

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::MAGIC_BYTES;
use crate::encoding::Encoding;

/// A container for the raw decoded byte vectors of the header sections.
#[derive(Debug)]
pub struct DecodedSections {
    /// Magic bytes identifying the file type.
    pub magic: Vec<u8>,

    /// Cryptographic salt for key derivation.
    pub salt: Vec<u8>,

    /// Serialized parameters (Parameters struct).
    pub header_data: Vec<u8>,

    /// Serialized metadata (Metadata struct).
    pub metadata: Vec<u8>,

    /// HMAC tag for integrity verification.
    pub mac: Vec<u8>,
}

/// Helper struct to store the lengths of the encoded sections.
///
/// This header is written first so the decoder knows how many bytes to read
/// for each subsequent section.
#[derive(Debug, Serialize, Deserialize, SchemaRead, SchemaWrite)]
struct LengthsHeader {
    /// Length of the encoded magic bytes section.
    magic_len: u32,

    /// Length of the encoded salt section.
    salt_len: u32,

    /// Length of the encoded parameters section.
    header_data_len: u32,

    /// Length of the encoded metadata section.
    metadata_len: u32,

    /// Length of the encoded MAC section.
    mac_len: u32,
}

impl LengthsHeader {
    /// The serialized size of the LengthsHeader struct in bytes.
    /// 5 fields * 4 bytes (u32) = 20 bytes.
    const SIZE: usize = 20;

    /// Converts the lengths to an array for easy iteration.
    fn as_array(&self) -> [u32; 5] {
        [self.magic_len, self.salt_len, self.header_data_len, self.metadata_len, self.mac_len]
    }
}

/// Handles the encoding and decoding of header sections.
///
/// The `SectionShield` ensures that header components are robust against corruption
/// by applying erasure coding before writing them to the stream.
#[derive(Debug)]
pub struct SectionShield {
    /// The Reed-Solomon encoder instance.
    encoder: Encoding,
}

impl SectionShield {
    /// Creates a new shield with the specified redundancy configuration.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of original data shards.
    /// * `parity_shards` - Number of recovery shards.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Packs the header components into a single byte vector ready for writing.
    ///
    /// # Process
    ///
    /// 1. Encodes each component (magic, salt, etc.) individually using RS.
    /// 2. Encodes the *lengths* of these encoded components (stored as 4-byte big-endian integers).
    ///    Wait, the code actually encodes the lengths of the *sections*? Let's check the code:
    ///    `self.encode_non_empty(&(section.len() as u32).to_be_bytes())` It creates a "length
    ///    section" for each data section. Then creates a `LengthsHeader` containing the lengths of
    ///    *those length sections*. Actually, looking at `pack`: It encodes the raw data ->
    ///    `sections`. Then it encodes the *lengths of those sections* -> `length_sections`. Then it
    ///    creates `LengthsHeader` with the sizes of `length_sections`. Finally writes
    ///    `LengthsHeader` + `length_sections` + `sections`. Wait, `for section in
    ///    length_sections.iter().chain(sections.iter())`. So the layout is: [LengthsHeader (fixed
    ///    20)] -> [Encoded Lengths of Sections] -> [Encoded Sections]
    ///
    /// This double-indirection seems complex but ensures that even the length descriptors
    /// are protected by RS encoding.
    pub fn pack(&self, magic: &[u8], salt: &[u8], header_data: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let raw_sections = [magic, salt, header_data, metadata, mac];

        // Step 1: RS-encode the actual content sections.
        let sections: Vec<Vec<u8>> = raw_sections.iter().map(|&data| self.encode_non_empty(data)).collect::<Result<Vec<Vec<u8>>>>()?;

        // Step 2: Create "length sections".
        // For each encoded content section, we take its length (u32), convert to bytes,
        // and RS-encode that 4-byte value. This protects the length information itself.
        let length_sections: Vec<Vec<u8>> = sections
            .iter()
            .map(|section| self.encode_non_empty(&(section.len() as u32).to_be_bytes()))
            .collect::<Result<Vec<Vec<u8>>>>()?;

        // Step 3: Create the master LengthsHeader.
        // This stores the size of the *encoded length sections*.
        // Since `encode_non_empty` output size depends on input size + parity, these sizes are predictable
        // but it's safer to store them explicitly.
        let lengths_header = LengthsHeader {
            magic_len: length_sections[0].len() as u32,
            salt_len: length_sections[1].len() as u32,
            header_data_len: length_sections[2].len() as u32,
            metadata_len: length_sections[3].len() as u32,
            mac_len: length_sections[4].len() as u32,
        };

        // Serialize the fixed-size master header.
        let mut result = wincode::serialize(&lengths_header)?;

        // Append all RS-encoded sections: first the length sections, then the content sections.
        for section in length_sections.iter().chain(sections.iter()) {
            result.extend_from_slice(section);
        }

        Ok(result)
    }

    /// RS-encodes a slice, ensuring it's not empty.
    fn encode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");
        self.encoder.encode(data)
    }

    /// RS-decodes a slice, ensuring input is valid.
    fn decode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "invalid encoded section");
        self.encoder.decode(data)
    }

    /// Reads and unpacks the header sections from an async reader.
    ///
    /// This reverses the `pack` process:
    /// 1. Read `LengthsHeader`.
    /// 2. Read and decode the "length sections".
    /// 3. Use those decoded lengths to read and decode the content sections.
    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<DecodedSections> {
        // Read the fixed-size master header.
        let mut buffer = [0u8; LengthsHeader::SIZE];
        reader.read_exact(&mut buffer).await.context("failed to read lengths header")?;

        let lengths_header: LengthsHeader = wincode::deserialize(&buffer).context("failed to deserialize lengths header")?;

        // Phase 1: Read and decode the lengths of the content sections.
        let section_lengths = self.read_and_decode_lengths(reader, &lengths_header).await?;

        // Phase 2: Read and decode the actual content sections.
        let sections = self.read_and_decode_sections(reader, &section_lengths).await?;

        Ok(sections)
    }

    /// Reads the encoded length sections and decodes them to get the actual content sizes.
    async fn read_and_decode_lengths<R: AsyncRead + Unpin>(&self, reader: &mut R, header: &LengthsHeader) -> Result<[u32; 5]> {
        let mut decoded_lengths = Vec::with_capacity(5);

        for (i, &size) in header.as_array().iter().enumerate() {
            // Read the encoded length block.
            let mut buffer = vec![0u8; size as usize];
            reader.read_exact(&mut buffer).await.with_context(|| format!("failed to read encoded length section {}", i))?;

            // Decode to get the original 4 bytes.
            let decoded = self.decode_non_empty(&buffer)?;

            ensure!(decoded.len() >= 4, "invalid length prefix size");

            // Convert bytes back to u32 (Big Endian).
            let length = u32::from_be_bytes(decoded[..4].try_into().map_err(|_| anyhow!("length conversion failed"))?);
            decoded_lengths.push(length);
        }

        // Convert vector to array.
        decoded_lengths.try_into().map_err(|_| anyhow!("failed to convert lengths vector to array"))
    }

    /// Reads and decodes the actual content sections using the lengths obtained in the previous
    /// step.
    async fn read_and_decode_sections<R: AsyncRead + Unpin>(&self, reader: &mut R, section_lengths: &[u32; 5]) -> Result<DecodedSections> {
        // Read and decode magic bytes.
        let magic = self.read_and_decode(reader, section_lengths[0], "magic").await?;

        // Verify magic bytes immediately.
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes");

        Ok(DecodedSections {
            magic,
            salt: self.read_and_decode(reader, section_lengths[1], "salt").await?,
            header_data: self.read_and_decode(reader, section_lengths[2], "header data").await?,
            metadata: self.read_and_decode(reader, section_lengths[3], "metadata").await?,
            mac: self.read_and_decode(reader, section_lengths[4], "mac").await?,
        })
    }

    /// Helper to read N bytes and decode them.
    async fn read_and_decode<R: AsyncRead + Unpin>(&self, reader: &mut R, size: u32, name: &str) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size as usize];

        reader.read_exact(&mut buffer).await.with_context(|| format!("failed to read encoded {}", name))?;

        self.decode_non_empty(&buffer)
    }
}
