use anyhow::{Result, anyhow};

use crate::compression::{Compression, Level};
use crate::crypto::{Aes, ChaCha, Cipher};
use crate::encoding::ErasureEncoder;
use crate::padding::Pkcs7Padding;
use crate::types::{Processing, Task, TaskResult};

use crate::stream::pool::BufferPool;

/// Worker responsible for processing individual data chunks.
///
/// The worker handles the core cryptographic and encoding operations:
/// - **Encryption**: Compression -> Padding -> AES-GCM -> XChaCha20 -> Erasure Encoding
/// - **Decryption**: Erasure Decoding -> XChaCha20 -> AES-GCM -> Unpadding -> Decompression
///
/// This worker is designed to process chunks of data in parallel, ensuring that the encryption or decryption pipeline
/// can handle large data sets efficiently.
pub struct ChunkWorker {
    compression: Compression,
    padding: Pkcs7Padding,
    aes: Aes,
    chacha: ChaCha,
    encoding: ErasureEncoder,
    mode: Processing,
    pool: BufferPool,
}

impl ChunkWorker {
    /// Creates a new worker with the specified key and mode.
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte key (32 bytes AES + 32 bytes ChaCha20).
    /// * `mode` - Processing mode (Encryption or Decryption).
    /// * `pool` - Buffer pool for memory management.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Self>`, where `Self` is the created `ChunkWorker` instance. If the key is invalid or
    /// any other error occurs during initialization, it returns an error.
    pub fn new(key: &[u8], mode: Processing, pool: BufferPool) -> Result<Self> {
        // Ensure the key is at least 64 bytes long (32 bytes for AES and 32 bytes for ChaCha)
        if key.len() < 64 {
            return Err(anyhow!("key must be at least 64 bytes"));
        }

        Ok(Self {
            compression: Compression::new(Level::BestSpeed), // Set compression to best speed
            padding: Pkcs7Padding::new(crate::padding::BLOCK_SIZE)?, // Set padding scheme (PKCS7)
            aes: Aes::new(&key[0..32])?, // Initialize AES with the first 32 bytes of the key
            chacha: ChaCha::new(&key[32..64])?, // Initialize ChaCha with the remaining 32 bytes of the key
            encoding: ErasureEncoder::new(
                crate::encoding::DATA_SHARDS,
                crate::encoding::PARITY_SHARDS,
            )?, // Initialize Erasure encoding (Reed-Solomon)
            mode,
            pool,
        })
    }

    /// Processes a single task (chunk).
    ///
    /// This method handles the core logic for encryption or decryption, depending on the `mode`.
    /// It also ensures that the input buffer is returned to the pool immediately after processing.
    ///
    /// # Arguments
    ///
    /// * `task` - The task to process, containing the chunk data and metadata.
    ///
    /// # Returns
    ///
    /// Returns a `TaskResult`, which contains the result of the operation (either encrypted or decrypted data),
    /// or an error if the operation fails.
    pub fn process(&self, task: Task) -> TaskResult {
        let input_size = task.data.len(); // Store the size of the input data
        let input_data = task.data; // Move the input data out of the task

        // Execute the appropriate pipeline (encryption or decryption)
        let result = match self.mode {
            Processing::Encryption => self.encrypt_pipeline(&input_data), // Encryption pipeline
            Processing::Decryption => self.decrypt_pipeline(&input_data), // Decryption pipeline
        };

        // Return the input buffer to the pool immediately to minimize memory usage
        self.pool.return_buffer(input_data);

        // Process the result and return the corresponding TaskResult
        match result {
            Ok(data) => {
                // Report the size for progress tracking
                let size = if self.mode == Processing::Encryption {
                    input_size // For encryption, report the original input size
                } else {
                    data.len() // For decryption, report the size of the decrypted data
                };
                TaskResult::new(task.index, data, size) // Create a result with the data and size
            }
            Err(e) => TaskResult::with_error(task.index, e), // Return an error if processing failed
        }
    }

    /// Executes the encryption pipeline steps.
    ///
    /// The encryption pipeline includes compression, padding, AES-GCM encryption, XChaCha20 encryption,
    /// and Erasure Encoding.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt.
    ///
    /// # Returns
    ///
    /// Returns the encrypted data as a `Result<Vec<u8>>`. If any step fails, an error is returned.
    fn encrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Compress the data to reduce its size before encryption
        let compressed = self.compression.compress(data)?;

        // 2. Pad the compressed data to align with AES block size
        let padded = self.padding.pad(&compressed)?;

        // 3. Encrypt the padded data with AES-GCM (inner encryption layer)
        let aes_encrypted = self.aes.encrypt(&padded)?;

        // 4. Encrypt the AES-encrypted data with XChaCha20-Poly1305 (outer encryption layer)
        let chacha_encrypted = self.chacha.encrypt(&aes_encrypted)?;

        // 5. Apply Reed-Solomon encoding (for error correction and redundancy)
        let encoded = self.encoding.encode(&chacha_encrypted)?;

        Ok(encoded) // Return the fully encrypted and encoded data
    }

    /// Executes the decryption pipeline steps (reverse of encryption).
    ///
    /// The decryption pipeline includes Reed-Solomon decoding, XChaCha20 decryption,
    /// AES-GCM decryption, unpadding, and decompression.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to decrypt.
    ///
    /// # Returns
    ///
    /// Returns the decrypted data as a `Result<Vec<u8>>`. If any step fails, an error is returned.
    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Decode the data using Reed-Solomon (error correction)
        let decoded = self.encoding.decode(data)?;

        // 2. Decrypt the decoded data with XChaCha20-Poly1305 (remove outer layer)
        let chacha_decrypted = self.chacha.decrypt(&decoded)?;

        // 3. Decrypt the XChaCha20-decrypted data with AES-GCM (remove inner layer)
        let aes_decrypted = self.aes.decrypt(&chacha_decrypted)?;

        // 4. Unpad the decrypted data (remove PKCS7 padding)
        let unpadded = self.padding.unpad(&aes_decrypted)?;

        // 5. Decompress the unpadded data to restore the original content
        let decompressed = self.compression.decompress(&unpadded)?;

        Ok(decompressed) // Return the fully decrypted and decompressed data
    }
}
