use anyhow::{Result, anyhow};

use crate::compression::{Compression, Level};
use crate::crypto::{Aes, ChaCha, Cipher};
use crate::encoding::ErasureEncoder;
use crate::padding::Pkcs7Padding;
use crate::types::{Processing, Task, TaskResult};

use crate::stream::pool::BufferPool;

const REQUIRED_KEY_LENGTH: usize = 64;
const AES_KEY_LENGTH: usize = 32;
const CHACHA_KEY_LENGTH: usize = 32;

/// Worker for processing individual data chunks through crypto pipeline.
///
/// Handles the core pipeline operations:
/// - **Encryption**: Compression → Padding → AES-GCM → XChaCha20 → Erasure Encoding
/// - **Decryption**: Erasure Decoding → XChaCha20 → AES-GCM → Unpadding → Decompression
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
    pub fn new(key: &[u8], mode: Processing, pool: BufferPool) -> Result<Self> {
        if key.len() < REQUIRED_KEY_LENGTH {
            return Err(anyhow!(
                "Encryption key must be exactly {} bytes ({}  for AES + {} for ChaCha20), got {} bytes",
                REQUIRED_KEY_LENGTH,
                AES_KEY_LENGTH,
                CHACHA_KEY_LENGTH,
                key.len()
            ));
        }

        Ok(Self {
            compression: Compression::new(Level::BestSpeed),
            padding: Pkcs7Padding::new(crate::padding::BLOCK_SIZE)?,
            aes: Aes::new(&key[0..AES_KEY_LENGTH])?,
            chacha: ChaCha::new(&key[AES_KEY_LENGTH..REQUIRED_KEY_LENGTH])?,
            encoding: ErasureEncoder::new(
                crate::encoding::DATA_SHARDS,
                crate::encoding::PARITY_SHARDS,
            )?,
            mode,
            pool,
        })
    }

    /// Processes a single task (chunk) through the appropriate pipeline.
    pub fn process(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();
        let input_data = task.data;

        let result = match self.mode {
            Processing::Encryption => self.encrypt_pipeline(&input_data),
            Processing::Decryption => self.decrypt_pipeline(&input_data),
        };

        self.pool.recycle(input_data);

        match result {
            Ok(data) => {
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

    fn encrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        let compressed = self.compression.compress(data)?;
        let padded = self.padding.pad(&compressed)?;
        let aes_encrypted = self.aes.encrypt(&padded)?;
        let chacha_encrypted = self.chacha.encrypt(&aes_encrypted)?;
        let encoded = self.encoding.encode(&chacha_encrypted)?;
        Ok(encoded)
    }

    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        let decoded = self.encoding.decode(data)?;
        let chacha_decrypted = self.chacha.decrypt(&decoded)?;
        let aes_decrypted = self.aes.decrypt(&chacha_decrypted)?;
        let unpadded = self.padding.unpad(&aes_decrypted)?;
        let decompressed = self.compression.decompress(&unpadded)?;
        Ok(decompressed)
    }
}
