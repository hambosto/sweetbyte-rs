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
/// -   **Encryption**: Compression -> Padding -> AES-GCM -> XChaCha20 -> Erasure Encoding
/// -   **Decryption**: Erasure Decoding -> XChaCha20 -> AES-GCM -> Unpadding -> Decompression
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
    /// * `mode` - Processing mode (Encryption/Decryption).
    /// * `pool` - Buffer pool for memory management.
    pub fn new(key: &[u8], mode: Processing, pool: BufferPool) -> Result<Self> {
        if key.len() < 64 {
            return Err(anyhow!("key must be at least 64 bytes"));
        }

        Ok(Self {
            compression: Compression::new(Level::BestSpeed),
            padding: Pkcs7Padding::new(crate::padding::BLOCK_SIZE)?,
            aes: Aes::new(&key[0..32])?,
            chacha: ChaCha::new(&key[32..64])?,
            encoding: ErasureEncoder::new(
                crate::encoding::DATA_SHARDS,
                crate::encoding::PARITY_SHARDS,
            )?,
            mode,
            pool,
        })
    }

    /// Processes a single task (chunk).
    ///
    /// This method executes the appropriate pipeline (encrypt/decrypt) and handles
    /// buffer management (returning input buffer to pool).
    pub fn process(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();
        let input_data = task.data; // Move data out of task

        let result = match self.mode {
            Processing::Encryption => self.encrypt_pipeline(&input_data),
            Processing::Decryption => self.decrypt_pipeline(&input_data),
        };

        // Return input buffer to pool immediately to keep memory usage low
        self.pool.return_buffer(input_data);

        match result {
            Ok(data) => {
                // Calculate size for progress reporting:
                // - Encryption: Report input size (bytes of original file processed)
                // - Decryption: Report output size (bytes of original file recovered)
                // This ensures the progress bar always reflects "original file bytes"
                let size = if self.mode == Processing::Encryption {
                    input_size
                } else {
                    data.len()
                };
                TaskResult::new(task.index, data, size)
            }
            Err(e) => TaskResult::with_error(task.index, e),
        }
    }

    /// Executes the encryption pipeline steps.
    fn encrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Compress: Reduce data size before encryption
        let compressed = self.compression.compress(data)?;

        // 2. Pad: Align to block size for AES
        let padded = self.padding.pad(&compressed)?;

        // 3. Encrypt with AES-GCM: Inner layer encryption
        let aes_encrypted = self.aes.encrypt(&padded)?;

        // 4. Encrypt with XChaCha20-Poly1305: Outer layer encryption
        let chacha_encrypted = self.chacha.encrypt(&aes_encrypted)?;

        // 5. Reed-Solomon encoding: Add redundancy for error correction
        let encoded = self.encoding.encode(&chacha_encrypted)?;

        Ok(encoded)
    }

    /// Executes the decryption pipeline steps (reverse of encryption).
    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Reed-Solomon decoding: Recover data from shards if needed
        let decoded = self.encoding.decode(data)?;

        // 2. Decrypt with XChaCha20-Poly1305: Remove outer layer
        let chacha_decrypted = self.chacha.decrypt(&decoded)?;

        // 3. Decrypt with AES-GCM: Remove inner layer
        let aes_decrypted = self.aes.decrypt(&chacha_decrypted)?;

        // 4. Unpad: Remove PKCS7 padding
        let unpadded = self.padding.unpad(&aes_decrypted)?;

        // 5. Decompress: Restore original data
        let decompressed = self.compression.decompress(&unpadded)?;

        Ok(decompressed)
    }
}
