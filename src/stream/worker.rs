use anyhow::{anyhow, Result};

use crate::compression::{Compression, Level};
use crate::crypto::{AesCipher, ChaCha20Cipher};
use crate::encoding::Encoding;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

use crate::stream::pool::BufferPool;

pub struct ChunkWorker {
    compression: Compression,
    padding: Padding,
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

        let aes_key = &key[0..32];
        let chacha_key = &key[32..64];

        Ok(Self {
            compression: Compression::new(Level::BestSpeed)?,
            padding: Padding::default(),
            aes_cipher: AesCipher::new(aes_key)?,
            chacha_cipher: ChaCha20Cipher::new(chacha_key)?,
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

        // TODO: Optimize intermediate allocations?
        // For now, we just use the pool for the final result if possible,
        // but the intermediate steps return new Vecs.
        // The final step `encode` returns a Vec.
        // We can't easily inject the pool into all these components without major refactoring.
        // But we can at least ensure the final result is what we return.
        // Actually, `process` returns `TaskResult` which owns the data.
        // The `encrypt_pipeline` returns a `Vec<u8>`.
        // If we want to use the pool, we need to copy into a pool buffer?
        // No, that adds a copy.
        // Unless we modify `Compression`, `Padding`, `Cipher`, `Encoding` to accept an output buffer.
        // That's a larger refactor.
        // For now, let's stick to returning the input buffer to the pool.
        // The output buffer is allocated by the libraries.
        // We can return it to the pool later in `StreamWriter`.

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
