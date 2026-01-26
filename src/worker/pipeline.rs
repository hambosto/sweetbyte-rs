//! Cryptographic processing pipeline for concurrent encryption/decryption
//!
//! This module implements the core data transformation pipeline that processes
//! each task through a series of cryptographic and compression operations.
//! The pipeline is designed for thread-safe concurrent access and optimal
/// performance for large-scale file processing.
///
/// ## Pipeline Architecture
///
/// The pipeline implements a layered approach to data security and performance:
///
/// ### Encryption Pipeline (Original → Encrypted)
/// 1. **Compression**: Reduces data size for faster processing and smaller output
/// 2. **Padding**: Ensures consistent block sizes for block cipher operations
/// 3. **AES-256-GCM**: High-performance authenticated encryption
/// 4. **XChaCha20-Poly1305**: Additional layer with different security properties
/// 5. **Reed-Solomon**: Adds erasure coding for data recovery (4+2 configuration)
///
/// ### Decryption Pipeline (Encrypted → Original)
/// 1. **Reed-Solomon**: Error correction and data reconstruction
/// 2. **XChaCha20-Poly1305**: First layer of decryption
/// 3. **AES-256-GCM**: Second layer of decryption
/// 4. **Unpadding**: Removes block alignment padding
/// 5. **Decompression**: Restores original data size
///
/// ## Security Design Rationale
///
/// - **Defense in Depth**: Multiple independent encryption layers
/// - **Algorithm Diversity**: Different cipher types prevent cascade failures
/// - **Authenticated Encryption**: Both ciphers provide integrity protection
/// - **Key Separation**: Each algorithm uses derived keys from the master key
/// - **Erasure Coding**: Protects against data corruption and partial loss
///
/// ## Performance Characteristics
///
/// - **Throughput**: Optimized for large data blocks with pipelined operations
/// - **Memory**: Minimal allocations; operations work on existing buffers
/// - **Parallelism**: Thread-safe design enables concurrent processing
/// - **CPU Utilization**: Balanced mix of compute and memory-bound operations
use anyhow::Result;

use crate::cipher::{Aes256Gcm, Cipher, XChaCha20Poly1305};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{ARGON_KEY_LEN, BLOCK_SIZE, DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

/// Multi-layer cryptographic processing pipeline
///
/// This struct orchestrates the complete data transformation process for both
/// encryption and decryption operations. It combines multiple cryptographic
/// primitives with compression and erasure coding to provide comprehensive
/// data protection and performance optimization.
///
/// ## Component Overview
///
/// - **cipher**: Manages dual encryption with AES-256-GCM and XChaCha20-Poly1305
/// - **encoder**: Reed-Solomon erasure coding for data recovery (4+2 configuration)
/// - **compressor**: LZ4-based compression for size reduction and processing speed
/// - **padding**: Block size alignment for optimal cipher performance
/// - **mode**: Determines processing direction (encryption vs decryption)
///
/// ## Thread Safety
///
/// The pipeline is designed to be thread-safe for read-only operations:
/// - All components are immutable after initialization
/// - No internal mutable state during processing
/// - Cryptographic keys are stored securely and shared safely
/// - Compatible with `Arc<T>` for concurrent access across threads
///
/// ## Performance Optimization
///
/// The pipeline is optimized for:
/// - **Large Blocks**: Processing efficiency scales with chunk size
/// - **Memory Efficiency**: Minimal allocations during processing
/// - **CPU Caches**: Sequential operations maintain good cache locality
/// - **Parallel Processing**: Thread-safe design enables concurrent execution
pub struct Pipeline {
    /// Dual cipher implementation for layered encryption
    /// Supports both AES-256-GCM and XChaCha20-Poly1305 algorithms
    /// Provides authenticated encryption with associated data (AEAD)
    cipher: Cipher,
    /// Reed-Solomon encoder for erasure coding
    /// 4 data shards + 2 parity shards configuration
    /// Enables recovery from up to 2 shard failures
    encoder: Encoding,
    /// Fast compression engine using LZ4 algorithm
    /// Configurable compression levels (set to Fast)
    /// Reduces data size for faster I/O and smaller storage
    compressor: Compressor,
    /// Block padding for cipher alignment
    /// Ensures data meets block cipher size requirements
    /// Uses PKCS#7-style padding for compatibility
    padding: Padding,
    /// Processing mode determining pipeline direction
    /// Affects the order and selection of operations
    mode: Processing,
}

impl Pipeline {
    /// Creates a new processing pipeline with the given encryption key and mode
    ///
    /// Initializes all cryptographic components and prepares the pipeline
    /// for either encryption or decryption operations.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Argon2-derived master key for cryptographic operations
    /// * `mode` - Processing mode (Encryption or Decryption)
    ///
    /// # Returns
    ///
    /// A fully initialized Pipeline ready for task processing
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Cipher initialization fails (key derivation, algorithm setup)
    /// - Reed-Solomon encoder creation fails (invalid shard configuration)
    /// - Compressor initialization fails (memory allocation, library error)
    /// - Padding configuration fails (invalid block size)
    ///
    /// # Security Notes
    ///
    /// The master key is immediately used to derive subkeys for each
    /// cryptographic component. This key separation prevents cross-contamination
    /// between different layers of encryption. All key material is handled
    /// securely and zeroed when components are dropped.
    ///
    /// # Performance Considerations
    ///
    /// Pipeline initialization is performed once and the resulting
    /// structure is shared across all processing threads. This design
    /// maximizes performance by:
    /// - Avoiding repeated key derivation operations
    /// - Reusing cryptographic contexts across multiple operations
    /// - Minimizing memory allocations during processing
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        // Initialize the dual cipher system with the master key
        // This creates separate subkeys for AES-256-GCM and XChaCha20-Poly1305
        let cipher = Cipher::new(key)?;

        // Setup Reed-Solomon erasure coding with 4+2 configuration
        // This allows recovery from up to 2 lost/corrupted data shards
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Initialize fast LZ4 compression for size optimization
        // Compression level is set to Fast for optimal throughput
        let compressor = Compressor::new(CompressionLevel::Fast)?;

        // Setup block padding for cipher alignment requirements
        // Ensures all data blocks meet minimum size for efficient processing
        let padding = Padding::new(BLOCK_SIZE)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    /// Processes a task through the appropriate pipeline
    ///
    /// This is the main entry point for task processing. Based on the pipeline's
    /// mode, it either encrypts or decrypts the task data through the complete
    /// transformation pipeline.
    ///
    /// # Arguments
    ///
    /// * `task` - The task containing data to be processed and its sequential index
    ///
    /// # Returns
    ///
    /// A TaskResult containing either the processed data or an error if any
    /// step in the pipeline fails. The result maintains the original task index
    /// for proper reordering in the output buffer.
    ///
    /// # Performance Characteristics
    ///
    /// - **Encryption Pipeline**: 5 sequential operations (compress → pad → encrypt → encrypt →
    ///   encode)
    /// - **Decryption Pipeline**: 5 sequential operations (decode → decrypt → decrypt → unpad →
    ///   decompress)
    /// - **Error Handling**: Early termination on first failure to minimize wasted processing
    /// - **Memory**: Operations work on existing data buffers when possible
    ///
    /// # Error Propagation
    ///
    /// Errors are captured immediately and wrapped in TaskResult with context:
    /// - Each operation's error is preserved with additional context
    /// - Task index is maintained for proper error reporting
    /// - Processing continues with other tasks even if individual tasks fail
    #[inline]
    pub fn process(&self, task: &Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    /// Processes data through the complete encryption pipeline
    ///
    /// Implements a multi-layer encryption strategy combining compression,
    /// dual encryption with different algorithms, and erasure coding for
    /// comprehensive data protection and performance optimization.
    ///
    /// ## Pipeline Stages
    ///
    /// 1. **Compression**: Reduces data size for faster processing and smaller output
    /// 2. **Padding**: Ensures proper block alignment for encryption operations
    /// 3. **AES-256-GCM**: First layer of authenticated encryption
    /// 4. **XChaCha20-Poly1305**: Second layer for defense in depth
    /// 5. **Reed-Solomon**: Adds erasure coding for data recovery capabilities
    ///
    /// ## Security Rationale
    ///
    /// **Algorithm Diversity**: Using different cipher families prevents cascade failures
    /// - **Authenticated Encryption**: Both layers provide integrity and authenticity
    /// - **Key Separation**: Each layer uses cryptographically independent subkeys
    /// - **Erasure Coding**: Protects against data corruption and partial data loss
    ///
    /// ## Performance Optimization
    ///
    /// - **Compression First**: Reduces data size before expensive encryption operations
    /// - **Sequential Processing**: Maintains good cache locality and memory efficiency
    /// - **Early Exit**: Immediate error return prevents wasted processing
    /// - **Minimal Allocations**: Reuses buffers when possible during transformations
    ///
    /// # Arguments
    ///
    /// * `task` - Task containing plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// TaskResult with encrypted data or error information
    ///
    /// # Error Handling
    ///
    /// Each stage performs comprehensive error checking:
    /// - Compression failures (memory, corruption)
    /// - Padding errors (size limits, alignment issues)
    /// - Encryption failures (key errors, data corruption)
    /// - Encoding errors (shard creation, memory allocation)
    fn encrypt_pipeline(&self, task: &Task) -> TaskResult {
        // Store original input size for progress tracking and size reporting
        // This is needed because the final encrypted size will be larger
        let input_size = task.data.len();

        // Stage 1: Compress the original data
        // Compression reduces data size, making subsequent encryption faster
        // LZ4 provides excellent speed with reasonable compression ratios
        let compressed_data = match self.compressor.compress(&task.data) {
            Ok(compressed) => compressed,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Stage 2: Pad compressed data to block cipher alignment
        // Ensures data meets minimum block size requirements for AES
        // Padding is essential for block cipher security and efficiency
        let padded_data = match self.padding.pad(&compressed_data) {
            Ok(padded) => padded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Stage 3: First encryption layer with AES-256-GCM
        // AES provides excellent performance on modern CPUs with AES-NI
        // GCM provides authenticated encryption for integrity protection
        let aes_encrypted = match self.cipher.encrypt::<Aes256Gcm>(&padded_data) {
            Ok(aes_encrypted) => aes_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Stage 4: Second encryption layer with XChaCha20-Poly1305
        // XChaCha20 provides security even if AES has implementation flaws
        // Different algorithm family prevents cascade failure scenarios
        let chacha_encrypted = match self.cipher.encrypt::<XChaCha20Poly1305>(&aes_encrypted) {
            Ok(chacha_encrypted) => chacha_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Stage 5: Apply Reed-Solomon erasure coding
        // Splits data into 4 data shards + 2 parity shards
        // Enables recovery from up to 2 lost/corrupted shards
        let encoded_data = match self.encoder.encode(&chacha_encrypted) {
            Ok(encoded) => encoded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Return successful result with final encrypted data
        // Original size is preserved for progress tracking purposes
        TaskResult::ok(task.index, encoded_data, input_size)
    }

    /// Processes data through the complete decryption pipeline
    ///
    /// Reverses the encryption pipeline operations in the correct order,
    /// performing error correction, dual decryption, unpadding, and
    /// decompression to restore the original data.
    ///
    /// ## Pipeline Stages (Reverse of Encryption)
    ///
    /// 1. **Reed-Solomon Decode**: Error correction and data reconstruction
    /// 2. **XChaCha20-Poly1305 Decrypt**: Removes outer encryption layer
    /// 3. **AES-256-GCM Decrypt**: Removes inner encryption layer
    /// 4. **Unpad**: Removes block alignment padding
    /// 5. **Decompress**: Restores original uncompressed data
    ///
    /// ## Error Recovery
    ///
    /// The decryption pipeline includes comprehensive error handling:
    /// - Reed-Solomon can recover from corrupted/missing data shards
    /// - Authentication failures in ciphers are detected and reported
    /// - Padding validation ensures data integrity
    /// - Decompression errors indicate potential corruption
    ///
    /// ## Security Validation
    ///
    /// Each decryption stage includes integrity validation:
    /// - Cipher authentication tags detect tampering
    /// - Padding validation checks for proper structure
    /// - Decompression validates data format consistency
    /// - Stage-specific context helps identify failure points
    ///
    /// # Arguments
    ///
    /// * `task` - Task containing encrypted data to decrypt
    ///
    /// # Returns
    ///
    /// TaskResult with decrypted data or detailed error information
    ///
    /// # Error Context
    ///
    /// Each error includes specific context to aid debugging:
    /// - "failed to decode data": Reed-Solomon reconstruction issues
    /// - "chacha20poly1305 decryption failed": Outer layer authentication failure
    /// - "aes256gcm decryption failed": Inner layer authentication failure
    /// - "padding validation failed": Invalid padding structure
    /// - "decompression failed": Data format or corruption issues
    fn decrypt_pipeline(&self, task: &Task) -> TaskResult {
        // Stage 1: Reed-Solomon decoding and error correction
        // Reconstructs original data from 4+2 shard configuration
        // Can recover from up to 2 missing or corrupted shards
        let decoded_data = match self.encoder.decode(&task.data) {
            Ok(decoded) => decoded,
            Err(e) => return TaskResult::err(task.index, &e.context("failed to decode data")),
        };

        // Stage 2: Remove XChaCha20-Poly1305 encryption layer
        // This is the outer encryption layer applied during encryption
        // Authentication tag verification ensures data integrity
        let chacha_decrypted = match self.cipher.decrypt::<XChaCha20Poly1305>(&decoded_data) {
            Ok(chacha_decrypted) => chacha_decrypted,
            Err(e) => return TaskResult::err(task.index, &e.context("chacha20poly1305 decryption failed")),
        };

        // Stage 3: Remove AES-256-GCM encryption layer
        // This is the inner encryption layer from the original encryption
        // GCM authentication provides additional integrity verification
        let aes_decrypted = match self.cipher.decrypt::<Aes256Gcm>(&chacha_decrypted) {
            Ok(aes_decrypted) => aes_decrypted,
            Err(e) => {
                return TaskResult::err(task.index, &e.context("aes256gcm decryption failed"));
            }
        };

        // Stage 4: Remove block padding applied before encryption
        // Validates padding structure and extracts original data
        // Invalid padding indicates potential tampering or corruption
        let unpadded_data = match self.padding.unpad(&aes_decrypted) {
            Ok(unpadded) => unpadded,
            Err(e) => return TaskResult::err(task.index, &e.context("padding validation failed")),
        };

        // Stage 5: Decompress data to restore original content
        // Reverses the LZ4 compression applied during encryption
        // Final step in restoring the original data
        let decompressed_data = match Compressor::decompress(&unpadded_data) {
            Ok(decompressed) => decompressed,
            Err(e) => return TaskResult::err(task.index, &e.context("decompression failed")),
        };

        // Store the final output size for progress tracking
        // This represents the actual size of the restored original data
        let output_size = decompressed_data.len();

        // Return successful result with restored original data
        TaskResult::ok(task.index, decompressed_data, output_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let pipeline_enc = Pipeline::new(&key, Processing::Encryption).unwrap();
        let pipeline_dec = Pipeline::new(&key, Processing::Decryption).unwrap();

        let data = b"Hello, secure world!";
        let task = Task { data: data.to_vec(), index: 0 };

        let encrypted = pipeline_enc.process(&task);
        assert!(encrypted.error.is_none());
        assert_ne!(encrypted.data, data);

        let task_dec = Task { data: encrypted.data, index: 0 };
        let decrypted = pipeline_dec.process(&task_dec);
        assert!(decrypted.error.is_none());
        assert_eq!(decrypted.data, data);
    }
}
