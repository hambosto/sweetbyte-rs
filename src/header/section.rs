//! Header section types and encoding.
//!
//! Defines the four header sections (Magic, Salt, HeaderData, Mac)
//! and provides Reed-Solomon encoding/decoding for each section.
//!
//! # Sections
//!
//! - **Magic**: 4 bytes, `0xCAFEBABE` - Identifies SweetByte files
//! - **Salt**: 32 bytes - Random salt for Argon2id
//! - **HeaderData**: 14 bytes - Version, flags, original size
//! - **Mac**: 32 bytes - HMAC-SHA256 authentication tag

use anyhow::{Result, anyhow, ensure};

use crate::encoding::Encoding;

/// Types of sections in the header.
///
/// Each section is Reed-Solomon encoded independently for resilience.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Magic bytes (0xCAFEBABE) - identifies file type.
    Magic = 0,

    /// Salt for key derivation (32 bytes).
    Salt = 1,

    /// Header metadata (version, flags, original_size).
    HeaderData = 2,

    /// HMAC authentication tag (32 bytes).
    Mac = 3,
}

impl SectionType {
    /// Array of all section types in order.
    pub const ALL: [Self; 4] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Mac];

    /// Returns the zero-based index of this section type.
    ///
    /// This allows using the SectionType as an array index for O(1) lookup.
    /// The indices are assigned based on the enum discriminant values:
    /// Magic=0, Salt=1, HeaderData=2, Mac=3.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        // Cast the enum to its underlying usize value.
        // This is a zero-cost conversion since enum discriminants are compile-time constants.
        self as usize
    }

    /// Returns a human-readable name for the section type.
    ///
    /// Used for error messages, logging, and debugging.
    /// Returns "Magic", "Salt", "HeaderData", or "Mac".
    #[must_use]
    pub const fn name(self) -> &'static str {
        // Pattern match on the enum variant to return the corresponding string.
        // const fn allows this to be evaluated at compile time.
        // match is exhaustive, covering all four variants.
        match self {
            Self::Magic => "Magic",
            Self::Salt => "Salt",
            Self::HeaderData => "HeaderData",
            Self::Mac => "Mac",
        }
    }
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A Reed-Solomon encoded section.
///
/// Contains encoded data that can be decoded to recover the original content,
/// even if some bytes are corrupted or missing.
#[derive(Debug, Clone)]
pub struct EncodedSection {
    /// The encoded data bytes.
    data: Vec<u8>,
}

impl EncodedSection {
    /// Creates a new encoded section.
    #[inline]
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns a reference to the encoded data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the encoded data in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the section has no data.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the length as a u32.
    #[inline]
    #[must_use]
    pub fn length_u32(&self) -> u32 {
        self.data.len() as u32
    }
}

/// Collection of decoded header sections.
///
/// Stores the four sections (Magic, Salt, HeaderData, Mac) in a fixed array.
pub struct Sections {
    /// The decoded sections, indexed by SectionType.
    sections: [Vec<u8>; 4],
}

impl Sections {
    /// Gets a section by type, returning None if not present.
    ///
    /// Looks up the section in the fixed-size array using the section type's index.
    /// Returns None if the section is empty (wasn't set during deserialization).
    ///
    /// # Arguments
    ///
    /// * `section_type` - Which section to retrieve (Magic, Salt, HeaderData, Mac).
    ///
    /// # Returns
    ///
    /// `Some(&[u8])` if the section exists and is non-empty, `None` otherwise.
    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        // Use the section type's index to access the corresponding array element.
        // This is O(1) lookup since arrays are indexed by position.
        let data = &self.sections[section_type.index()];

        // Return None if the section is empty (empty Vec means unset).
        // This distinguishes between "section was never set" and "section has zero bytes".
        if data.is_empty() { None } else { Some(data) }
    }

    /// Gets a section, verifying it meets minimum length requirement.
    ///
    /// This is a convenience method that combines lookup with length validation.
    /// It's commonly used when reading header data to ensure sufficient bytes.
    ///
    /// # Arguments
    ///
    /// * `section_type` - Which section to retrieve.
    /// * `min_len` - Minimum number of bytes required (e.g., MAGIC_SIZE = 4).
    ///
    /// # Returns
    ///
    /// A slice of exactly min_len bytes from the section.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The section is missing (wasn't set during deserialization)
    /// - The section has fewer than min_len bytes
    pub fn get_with_min_len(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        // First, try to get the section.
        // ok_or_else converts None to an error with a descriptive message.
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;

        // Validate that the section has enough data for the expected read.
        // ensure! macro creates an error if the condition is false.
        // This catches truncated or corrupted sections.
        ensure!(data.len() >= min_len, "{} section too short: expected at least {}, got {}", section_type, min_len, data.len());

        // Return a slice of exactly min_len bytes.
        // The slice borrows from self, lifetime tied to self.
        Ok(&data[..min_len])
    }
}

/// Builder for constructing a Sections instance.
///
/// Ensures all required sections are present before creating the immutable Sections.
pub struct SectionsBuilder {
    /// Optional section data, indexed by SectionType.
    sections: [Option<Vec<u8>>; 4],
}

impl SectionsBuilder {
    /// Creates a builder with the Magic section already set.
    ///
    /// The Magic section is always required and is read first during deserialization.
    /// This constructor pre-fills the first array slot with the magic bytes.
    ///
    /// # Arguments
    ///
    /// * `magic` - The magic bytes (4 bytes, typically 0xCAFEBABE).
    ///
    /// # Returns
    ///
    /// A builder with Magic set and other sections empty (None).
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        // Initialize sections array with Some for magic, None for others.
        // Array syntax [a, b, c, d] creates the fixed-size array.
        // The order corresponds to SectionType index: Magic=0, Salt=1, HeaderData=2, Mac=3.
        Self { sections: [Some(magic), None, None, None] }
    }

    /// Sets a section value.
    ///
    /// Stores the provided data in the specified section slot.
    /// Sections can be set in any order; the build() method validates completeness.
    ///
    /// # Arguments
    ///
    /// * `section_type` - Which section to set (Salt, HeaderData, or Mac).
    /// * `value` - The section data as owned bytes.
    ///
    /// # Returns
    ///
    /// Mutable reference to self for method chaining.
    /// This enables pattern: builder.set(A, x).set(B, y).set(C, z).build()
    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        // Use the section type's index to determine array position.
        // Index 0 = Magic (already set), 1 = Salt, 2 = HeaderData, 3 = Mac.
        // Overwrite the None with Some(value) to mark this section as set.
        self.sections[section_type.index()] = Some(value);

        // Return mutable self to enable chained calls.
        // Each set() call mutates the builder, returning &mut Self.
        self
    }

    /// Builds the Sections, validating all sections are present and non-empty.
    ///
    /// This method performs the final validation and transformation from the
    /// builder's optional sections to the immutable Sections struct.
    ///
    /// The build process:
    /// 1. Consumes the builder (takes ownership) since it's single-use
    /// 2. Converts `Option<Vec<u8>>` array into an iterator
    /// 3. Zips with SectionType::ALL to associate each section with its type
    /// 4. Validates each section is present (Some) and non-empty
    /// 5. Collects valid sections into a Vec
    /// 6. Converts Vec to fixed-size array [`Vec<u8>`; 4]
    /// 7. Returns the immutable Sections struct
    ///
    /// # Errors
    ///
    /// Returns an error if any section is missing or empty.
    pub fn build(self) -> Result<Sections> {
        // Convert the [`Option<Vec<u8>>`; 4] into an iterator.
        // into_iter() takes ownership of each element.
        // This is necessary because we're consuming the builder.
        let sections = self
            .sections
            .into_iter()
            // Zip pairs each section with its corresponding SectionType.
            // SectionType::ALL = [Magic, Salt, HeaderData, Mac]
            // This gives us both the optional data AND the type name for error messages.
            .zip(SectionType::ALL)
            // Map each (`Option<Vec<u8>>`, SectionType) pair to Result<Vec<u8>>.
            // The iterator adapter processes each pair individually.
            .map(|(opt, ty)| {
                // Check if the section was set (Some) or not (None).
                // ok_or_else converts None to an error, Some unwraps to the data.
                // This ensures all required sections are present.
                let data = opt.ok_or_else(|| anyhow!("{ty} section is missing"))?;

                // Validate that the section data is not empty.
                // Empty sections indicate incomplete or malformed data.
                // This catches cases where a section was set but has no content.
                ensure!(!data.is_empty(), "{ty} section is empty");

                // Return the validated data wrapped in Ok.
                // The ? operator in the outer closure will handle this Result.
                Ok(data)
            })
            // Collect the iterator of Result<Vec<u8>> into a single Result<Vec<Vec<u8>>>.
            // If any section failed validation, collect() propagates the first error.
            .collect::<Result<Vec<Vec<u8>>>>()?;

        // Convert the Vec<Vec<u8>> into a fixed-size array [`Vec<u8>`; 4].
        // try_into() attempts the conversion, which succeeds only if len() == 4.
        // This is guaranteed by our zip with SectionType::ALL, but we validate anyway.
        // The map_err provides a fallback error if the count is wrong (shouldn't happen).
        Ok(Sections { sections: sections.try_into().map_err(|_| anyhow!("unexpected section count"))? })
    }
}

/// Encoder for Reed-Solomon protecting header sections.
///
/// Each section and its length are Reed-Solomon encoded independently,
/// allowing recovery from partial corruption.
pub struct SectionEncoder {
    /// The underlying Reed-Solomon encoder.
    encoder: Encoding,
}

impl SectionEncoder {
    /// Creates a new section encoder with the specified shard counts.
    ///
    /// The SectionEncoder wraps the underlying Reed-Solomon Encoding
    /// with section-specific validation and type conversion.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards (default: 4).
    /// * `parity_shards` - Number of parity shards for error correction (default: 10).
    ///
    /// # Returns
    ///
    /// A new SectionEncoder wrapped in Result (for encoding creation errors).
    ///
    /// # Errors
    ///
    /// Returns an error if the Reed-Solomon encoding cannot be created
    /// with the specified shard counts (e.g., invalid shard configuration).
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        // Create the underlying Reed-Solomon encoder.
        // This may fail if shard counts are invalid for the encoder.
        let encoder = Encoding::new(data_shards, parity_shards)?;

        // Wrap in our SectionEncoder struct.
        // Return Ok to indicate successful creation.
        Ok(Self { encoder })
    }

    /// Encodes a section using Reed-Solomon.
    ///
    /// Takes raw section data and adds Reed-Solomon parity for error correction.
    /// The output is larger than the input due to added parity bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw section data (e.g., 4 bytes for Magic, 32 bytes for Salt).
    ///
    /// # Returns
    ///
    /// An EncodedSection containing the raw data plus Reed-Solomon parity.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input data is empty (nothing to encode)
    /// - The underlying Reed-Solomon encoding fails
    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        // Validate that we have data to encode.
        // Empty sections are not allowed as they provide no redundancy.
        ensure!(!data.is_empty(), "data cannot be empty");

        // Pass data to the underlying Reed-Solomon encoder.
        // This splits data into shards, computes parity, and returns combined output.
        // The ? operator propagates any encoding errors.
        let encoded = self.encoder.encode(data)?;

        // Wrap the encoded bytes in an EncodedSection struct.
        // This provides a typed container for the encoded data.
        Ok(EncodedSection::new(encoded))
    }

    /// Encodes a length value using Reed-Solomon.
    ///
    /// Converts a u32 length into a 4-byte big-endian representation,
    /// then applies Reed-Solomon encoding for corruption resistance.
    /// This is used to encode section lengths in the header's length prefix.
    ///
    /// # Arguments
    ///
    /// * `length` - The length value to encode (e.g., encoded section size in bytes).
    ///
    /// # Returns
    ///
    /// An EncodedSection containing the encoded length.
    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        // Convert the u32 to a 4-byte big-endian array.
        // to_be_bytes() creates [0u8; 4] with the value in network byte order.
        // This ensures consistent byte order across different architectures.
        let bytes = length.to_be_bytes();

        // Delegate to encode_section which handles the Reed-Solomon encoding.
        // This reuses the section encoding logic for length values.
        self.encode_section(&bytes)
    }

    /// Decodes a section, recovering from corruption.
    ///
    /// Reverses the encode_section() process using Reed-Solomon error correction.
    /// This can recover the original data even if some bytes are corrupted or missing,
    /// as long as at least data_shards worth of good data remains.
    ///
    /// # Arguments
    ///
    /// * `section` - The Reed-Solomon encoded section containing data + parity.
    ///
    /// # Returns
    ///
    /// The decoded original section content.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The section is empty (no encoded data to decode)
    /// - Too many bytes are corrupted to recover (exceeds parity capacity)
    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        // Validate that we have encoded data to decode.
        // Empty sections indicate malformed or incomplete input.
        ensure!(!section.is_empty(), "invalid encoded section");

        // Pass encoded data to the underlying Reed-Solomon decoder.
        // This will attempt reconstruction if the data is corrupted.
        // The encoder.decode() handles the algebraic recovery process.
        // The ? propagates any errors (e.g., too many corrupted shards).
        self.encoder.decode(section.data())
    }

    /// Decodes a length value from its Reed-Solomon encoding.
    ///
    /// Reverses the encode_length() process:
    /// 1. Decodes the Reed-Solomon section to recover the 4-byte length
    /// 2. Converts from big-endian bytes back to u32
    ///
    /// # Arguments
    ///
    /// * `section` - The Reed-Solomon encoded section containing the length data.
    ///
    /// # Returns
    ///
    /// The decoded length as a u32.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The section decoding fails (too corrupted to recover)
    /// - The decoded data is shorter than 4 bytes (malformed length)
    /// - The u32 conversion fails (shouldn't happen with proper slice)
    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        // First, decode the Reed-Solomon section to get the raw 4 bytes.
        // This will attempt reconstruction if the section is corrupted.
        // The ? propagates any decoding errors.
        let decoded = self.decode_section(section)?;

        // Validate that we got at least 4 bytes for the u32.
        // This catches malformed or truncated length sections.
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        // Convert the first 4 bytes from big-endian back to u32.
        // decoded[..4] takes exactly 4 bytes.
        // try_into() converts [u8; 4] to u32.
        // The map_err provides a fallback error if the slice conversion fails.
        // This shouldn't happen with proper bounds checking, but we handle it.
        Ok(u32::from_be_bytes(decoded[..4].try_into().map_err(|_| anyhow!("length conversion failed"))?))
    }
}
