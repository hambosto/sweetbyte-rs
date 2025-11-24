use anyhow::{anyhow, Result};

use crate::compression::{Compression, Level};
use crate::crypto::{AesCipher, ChaCha20Cipher};
use crate::encoding::Encoding;
use crate::padding::Pkcs7Padding;
use crate::types::{Processing, Task, TaskResult};

use crate::stream::pool::BufferPool;

pub struct ChunkWorker {
    compression: Compression,
    padding: Pkcs7Padding,
    aes_cipher: AesCipher,
    chacha_cipher: ChaCha20Cipher,
    encoding: Encoding,
    mode: Processing,
    pool: BufferPool,
}

impl ChunkWorker {
    pub fn new(key: &[u8], mode: Processing, pool: BufferPool) -> Result<Self> {
        if key.len() < 64 {
            return Err(anyhow!("key must be at least 64 bytes"));
        }

        Ok(Self {
            compression: Compression::new(Level::BestSpeed)?,
            padding: Pkcs7Padding::new(crate::padding::BLOCK_SIZE)?,
            aes_cipher: AesCipher::new(&key[0..32])?,
            chacha_cipher: ChaCha20Cipher::new(&key[32..64])?,
            encoding: Encoding::new(crate::encoding::DATA_SHARDS, crate::encoding::PARITY_SHARDS)?,
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
        let aes_encrypted = self.aes_cipher.encrypt(&padded)?;

        // 4. Encrypt with XChaCha20-Poly1305
        let chacha_encrypted = self.chacha_cipher.encrypt(&aes_encrypted)?;

        // 5. Reed-Solomon encoding
        let encoded = self.encoding.encode(&chacha_encrypted)?;

        // OPTIMIZATION OPPORTUNITY: Intermediate Allocations
        //
        // Current pipeline allocates 5 Vec<u8> per chunk:
        //   1. compress() -> Vec
        //   2. pad() -> Vec
        //   3. aes_cipher.encrypt() -> Vec
        //   4. chacha_cipher.encrypt() -> Vec
        //   5. encoding.encode() -> Vec
        //
        // Potential optimization (requires API changes to crypto/compression modules):
        //   - Modify each component to accept `&mut Vec<u8>` output buffer
        //   - Reuse single buffer from pool across all steps
        //   - Would reduce allocations from 5 per chunk to 1 per chunk
        //   - Expected performance gain: 20-30% reduction in memory allocations
        //
        // Current approach:
        //   - Input buffer returned to pool in `process()`
        //   - Output buffer allocated by pipeline, returned to pool in `StreamWriter`
        //   - Intermediate buffers allocated/deallocated per chunk (overhead)

        Ok(encoded)
    }

    fn decrypt_pipeline(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Reed-Solomon decoding
        let decoded = self.encoding.decode(data)?;

        // 2. Decrypt with XChaCha20-Poly1305
        let chacha_decrypted = self.chacha_cipher.decrypt(&decoded)?;

        // 3. Decrypt with AES-GCM
        let aes_decrypted = self.aes_cipher.decrypt(&chacha_decrypted)?;

        // 4. Unpad
        let unpadded = self.padding.unpad(&aes_decrypted)?;

        // 5. Decompress
        let decompressed = self.compression.decompress(&unpadded)?;

        Ok(decompressed)
    }
}
