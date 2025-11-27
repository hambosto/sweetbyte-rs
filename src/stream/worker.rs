use anyhow::{Context, Result, anyhow};

use crate::compression::{Compression, Level};
use crate::crypto::{Aes, ChaCha, Cipher};
use crate::encoding::ErasureEncoder;
use crate::padding::Pkcs7Padding;
use crate::types::{Processing, Task, TaskResult};

const REQUIRED_KEY_LENGTH: usize = 64;
const AES_KEY_LENGTH: usize = 32;

/// Processor for individual encryption/decryption tasks.
///
/// Handles the core cryptographic pipeline operations:
/// - **Encryption**: Compression → Padding → AES-256-GCM → XChaCha20-Poly1305 → Reed-Solomon
/// - **Decryption**: Reed-Solomon → XChaCha20-Poly1305 → AES-256-GCM → Unpadding → Decompression
///
/// This matches Go's TaskProcessor and is designed to be called from worker threads.
pub struct ChunkWorker {
    first_cipher: Aes,
    second_cipher: ChaCha,
    encoder: ErasureEncoder,
    compressor: Compression,
    padding: Pkcs7Padding,
    processing: Processing,
}

impl ChunkWorker {
    /// Creates a new task processor with the specified key and mode.
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte key (32 bytes for AES-256-GCM + 32 bytes for XChaCha20-Poly1305)
    /// * `processing` - Processing mode (Encryption or Decryption)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key length is not exactly 64 bytes
    /// - Cipher initialization fails
    /// - Encoder initialization fails
    pub fn new(key: &[u8], processing: Processing) -> Result<Self> {
        if key.len() < REQUIRED_KEY_LENGTH {
            return Err(anyhow!(
                "encryption key must be at least {} bytes long, got {} bytes",
                REQUIRED_KEY_LENGTH,
                key.len()
            ));
        }

        let first_cipher =
            Aes::new(&key[0..AES_KEY_LENGTH]).context("failed to initialize AES-256-GCM cipher")?;

        let second_cipher = ChaCha::new(&key[AES_KEY_LENGTH..REQUIRED_KEY_LENGTH])
            .context("failed to initialize XChaCha20-Poly1305 cipher")?;

        let encoder =
            ErasureEncoder::new(crate::encoding::DATA_SHARDS, crate::encoding::PARITY_SHARDS)
                .context("failed to initialize Reed-Solomon encoder")?;

        let compressor = Compression::new(Level::BestSpeed);

        let padding = Pkcs7Padding::new(crate::padding::BLOCK_SIZE)
            .context("failed to initialize PKCS#7 padding")?;

        Ok(Self {
            first_cipher,
            second_cipher,
            encoder,
            compressor,
            padding,
            processing,
        })
    }

    /// Processes a single task through the appropriate pipeline.
    ///
    /// This is a synchronous, blocking operation designed to be called from worker threads.
    /// Returns a TaskResult with either the processed data or an error.
    pub fn process(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();
        let index = task.index;

        let result = match self.processing {
            Processing::Encryption => self.encrypt_pipeline(&task.data),
            Processing::Decryption => self.decrypt_pipeline(&task.data),
        };

        match result {
            Ok(data) => {
                let size = if self.processing == Processing::Encryption {
                    input_size
                } else {
                    data.len()
                };
                TaskResult::new(index, data, size)
            }
            Err(e) => TaskResult::with_error(index, e),
        }
    }

    /// Encryption pipeline: Compress → Pad → AES → ChaCha → Reed-Solomon
    #[inline]
    fn encrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.compressor
            .compress(data)
            .context("compression failed")
            .and_then(|compressed| self.padding.pad(&compressed).context("padding failed"))
            .and_then(|padded| {
                self.first_cipher
                    .encrypt(&padded)
                    .context("AES-256-GCM encryption failed")
            })
            .and_then(|aes_encrypted| {
                self.second_cipher
                    .encrypt(&aes_encrypted)
                    .context("XChaCha20-Poly1305 encryption failed")
            })
            .and_then(|chacha_encrypted| {
                self.encoder
                    .encode(&chacha_encrypted)
                    .context("Reed-Solomon encoding failed")
            })
    }

    /// Decryption pipeline: Reed-Solomon → ChaCha → AES → Unpad → Decompress
    #[inline]
    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.encoder
            .decode(data)
            .context("Reed-Solomon decoding failed (data may be corrupted)")
            .and_then(|decoded| {
                self.second_cipher
                    .decrypt(&decoded)
                    .context("XChaCha20-Poly1305 decryption failed (possible tampering)")
            })
            .and_then(|chacha_decrypted| {
                self.first_cipher
                    .decrypt(&chacha_decrypted)
                    .context("AES-256-GCM decryption failed (possible tampering)")
            })
            .and_then(|aes_decrypted| {
                self.padding
                    .unpad(&aes_decrypted)
                    .context("padding validation failed (possible tampering)")
            })
            .and_then(|unpadded| {
                self.compressor
                    .decompress(&unpadded)
                    .context("decompression failed (possible corruption)")
            })
    }
}
