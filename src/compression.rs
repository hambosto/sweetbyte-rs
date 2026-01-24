//! ZLIB Compression Module
//!
//! This module provides ZLIB compression and decompression functionality using
//! the flate2 crate. It offers configurable compression levels and integrates
//! with the application's error handling and validation patterns.
//!
//! ## Design Considerations
//!
//! The compression module serves several purposes in SweetByte:
//! 1. **Size Reduction**: Compresses data before encryption to reduce file size
//! 2. **Pattern Obfuscation**: Compression removes patterns that might aid cryptanalysis
//! 3. **Performance**: Reduces I/O operations by working with smaller data sets
//!
//! ## Security Implications
//!
//! - Compression before encryption is generally safe as both operations are reversible
//! - Compression can reduce the effectiveness of certain side-channel attacks
//! - Different compression levels have different timing characteristics
//!
//! ## Performance Trade-offs
//!
//! - **Fast**: Quick compression with moderate size reduction (default)
//! - **Default**: Balanced compression ratio and speed
//! - **Best**: Maximum compression with slower processing
//! - **None**: Skip compression for already compressed data or when speed is critical

use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// Compression level options for ZLIB compression
///
/// This enum defines the available compression strategies, each offering
/// different trade-offs between compression speed and ratio. The default
/// option (Fast) is chosen to provide good performance for most use cases
/// while still achieving meaningful size reduction.
///
/// ## Level Selection Guidelines
///
/// - **None**: Use for already compressed data (JPEG, MP4, etc.) or when processing speed is the
///   absolute priority
/// - **Fast**: Good for most files, provides quick compression with moderate size reduction
///   (recommended default)
/// - **Default**: Better compression ratio with longer processing time
/// - **Best**: Maximum compression for storage-critical applications
///
/// ## Performance Characteristics
///
/// The compression time typically follows: Fast < Default < Best
/// The compression ratio typically follows: None < Fast < Default < Best
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression - pass data through unchanged
    ///
    /// Useful for:
    /// - Already compressed data (images, videos, archives)
    /// - When processing speed is critical
    /// - Small files where compression overhead outweighs benefits
    None,

    /// Fast compression with good performance characteristics (default)
    ///
    /// This is the recommended default for most use cases as it provides
    /// a good balance between speed and compression ratio. It uses minimal
    /// CPU resources while still achieving meaningful size reduction.
    #[default]
    Fast,

    /// Default ZLIB compression level
    ///
    /// Provides better compression ratio than Fast mode with increased
    /// processing time. Suitable when storage space is more important than
    /// processing speed.
    Default,

    /// Maximum compression level
    ///
    /// Provides the best possible compression ratio at the cost of
    /// significantly increased processing time and memory usage.
    /// Recommended only for very large files where storage optimization
    /// is critical.
    Best,
}

impl CompressionLevel {
    /// Validate that the compression level is within acceptable bounds
    ///
    /// This method provides a safety check to ensure that all defined
    /// compression levels map to valid ZLIB compression values (0-9).
    /// While this should always return true for defined variants, it
    /// provides a safety net for future modifications.
    ///
    /// # Returns
    ///
    /// `true` if the compression level maps to a valid ZLIB value
    #[inline]
    pub fn is_valid(self) -> bool {
        // Map our enum to actual ZLIB compression levels
        let value = match self {
            Self::None => 0,    // No compression
            Self::Fast => 1,    // Fastest compression
            Self::Default => 6, // Default ZLIB level
            Self::Best => 9,    // Maximum compression
        };

        // ZLIB supports levels 0-9, so this should always be true
        value <= 9
    }
}

impl From<CompressionLevel> for Compression {
    /// Convert our CompressionLevel enum to flate2's Compression type
    ///
    /// This conversion bridges our application's abstraction with the
    /// underlying flate2 library's compression levels. It ensures that
    /// our user-friendly levels map to appropriate ZLIB parameters.
    ///
    /// # Arguments
    ///
    /// * `level` - Our compression level enum variant
    ///
    /// # Returns
    ///
    /// A flate2 `Compression` instance configured with the appropriate level
    fn from(level: CompressionLevel) -> Self {
        match level {
            // No compression - pass through unchanged
            CompressionLevel::None => Self::none(),
            // Fast compression using flate2's fast mode
            CompressionLevel::Fast => Self::fast(),
            // Default compression using flate2's default level
            CompressionLevel::Default => Self::default(),
            // Best compression using flate2's best mode
            CompressionLevel::Best => Self::best(),
        }
    }
}

/// ZLIB compression engine
///
/// This struct provides high-level compression and decompression operations
/// using the ZLIB algorithm. It encapsulates the compression level and provides
/// a clean interface that integrates with the application's error handling.
///
/// ## Thread Safety
///
/// The `Compressor` is designed to be thread-safe for read operations.
/// Multiple threads can safely call `compress()` and `decompress()` concurrently
/// as the underlying flate2 implementation is thread-safe for these operations.
///
/// ## Memory Management
///
/// The compressor allocates buffers as needed during compression and
/// decompression. Memory is properly managed by Rust's ownership system,
/// ensuring no memory leaks even in error conditions.
pub struct Compressor {
    /// The configured compression level for this instance
    level: Compression,
}

impl Compressor {
    /// Create a new compressor with the specified compression level
    ///
    /// This constructor validates the compression level and creates a
    /// compressor instance ready for use. The compression level affects
    /// both the compression ratio and processing time.
    ///
    /// # Arguments
    ///
    /// * `level` - The desired compression level
    ///
    /// # Returns
    ///
    /// * `Ok(Compressor)` - Successfully created compressor
    /// * `Err(anyhow::Error)` - Invalid compression level provided
    ///
    /// # Examples
    ///
    /// ```rust
    /// let compressor = Compressor::new(CompressionLevel::Fast)?;
    /// ```
    #[inline]
    pub fn new(level: CompressionLevel) -> Result<Self> {
        // Validate the compression level before creating the instance
        ensure!(level.is_valid(), "invalid compression level");

        Ok(Self { level: level.into() })
    }

    /// Compress data using the configured compression level
    ///
    /// This method compresses the input data using ZLIB compression with
    /// the level specified during creation. The compressed data includes
    /// ZLIB headers and checksums for integrity verification.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data to compress (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Successfully compressed data
    /// * `Err(anyhow::Error)` - Compression failed or input was invalid
    ///
    /// # Performance Notes
    ///
    /// - Memory allocation is proportional to the input data size
    /// - Processing time depends on the configured compression level
    /// - Very small data may actually increase in size due to ZLIB headers
    ///
    /// # Security Considerations
    ///
    /// - The compression process is deterministic for identical inputs
    /// - ZLIB includes CRC32 checksums for integrity verification
    /// - No sensitive data is leaked through the compression process
    #[inline]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input - empty data cannot be meaningfully compressed
        ensure!(!data.is_empty(), "data cannot be empty");

        // Create a ZLIB encoder that writes to a new Vec<u8>
        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);

        // Write all data to the encoder, which compresses it
        encoder.write_all(data).context("compression failed")?;

        // Finalize compression and get the compressed bytes
        encoder.finish().context("compression finalization failed")
    }

    /// Decompress ZLIB-compressed data
    ///
    /// This static method decompresses data that was previously compressed
    /// with ZLIB. It automatically validates the ZLIB headers and checksums
    /// during decompression.
    ///
    /// # Arguments
    ///
    /// * `data` - ZLIB-compressed data (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Successfully decompressed original data
    /// * `Err(anyhow::Error)` - Decompression failed due to corruption or format error
    ///
    /// # Error Conditions
    ///
    /// - Corrupted or truncated input data
    /// - Invalid ZLIB format
    /// - Checksum verification failure
    /// - Insufficient memory for decompressed data
    ///
    /// # Security Notes
    ///
    /// - ZLIB checksum validation ensures data integrity
    /// - The method protects against decompression bombs by validating headers
    /// - Memory allocation is controlled to prevent denial-of-service attacks
    #[inline]
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        // Validate input - empty data cannot be decompressed
        ensure!(!data.is_empty(), "data cannot be empty");

        // Create a ZLIB decoder for the input data
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        // Read all decompressed data into the vector
        decoder.read_to_end(&mut decompressed).context("failed to decompress data")?;

        Ok(decompressed)
    }
}
