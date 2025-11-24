use anyhow::{anyhow, Result};

use crate::compression::{Compression, Level};
use crate::crypto::{Aes, ChaCha, Cipher};
use crate::encoding::ErasureEncoder;
use crate::padding::Pkcs7Padding;
use crate::types::{Processing, Task, TaskResult};

use crate::stream::pool::BufferPool;

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

    pub fn process(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();
        let input_data = task.data; // Move data out of task

        let result = match self.mode {
            Processing::Encryption => self.encrypt_pipeline(&input_data),
            Processing::Decryption => self.decrypt_pipeline(&input_data),
        };

        // Return input buffer to pool
        self.pool.return_buffer(input_data);

        match result {
            Ok(data) => {
                // For encryption: report input size (original data)
                // For decryption: report output size (decrypted data)
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
        // 1. Compress
        let compressed = self.compression.compress(data)?;

        // 2. Pad
        let padded = self.padding.pad(&compressed)?;

        // 3. Encrypt with AES-GCM
        let aes_encrypted = self.aes.encrypt(&padded)?;

        // 4. Encrypt with XChaCha20-Poly1305
        let chacha_encrypted = self.chacha.encrypt(&aes_encrypted)?;

        // 5. Reed-Solomon encoding
        let encoded = self.encoding.encode(&chacha_encrypted)?;

        Ok(encoded)
    }

    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Reed-Solomon decoding
        let decoded = self.encoding.decode(data)?;

        // 2. Decrypt with XChaCha20-Poly1305
        let chacha_decrypted = self.chacha.decrypt(&decoded)?;

        // 3. Decrypt with AES-GCM
        let aes_decrypted = self.aes.decrypt(&chacha_decrypted)?;

        // 4. Unpad
        let unpadded = self.padding.unpad(&aes_decrypted)?;

        // 5. Decompress
        let decompressed = self.compression.decompress(&unpadded)?;

        Ok(decompressed)
    }
}
