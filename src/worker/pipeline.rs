use anyhow::Result;

use crate::cipher::{Cipher, CipherAlgorithm};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::{BlockSize, Pkcs7Padding};
use crate::secret::SecretBytes;
use crate::types::{Processing, Task, TaskResult};

pub struct Pipeline {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compressor,
    padding: Pkcs7Padding,
    mode: Processing,
}

impl Pipeline {
    pub fn new(key: &SecretBytes, mode: Processing) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        let compressor = Compressor::new(CompressionLevel::Fast)?;
        let padding = Pkcs7Padding::new(BlockSize::B128)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    pub fn process(&self, task: &Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: &Task) -> TaskResult {
        let compressed_data = match self.compressor.compress(&task.data) {
            Ok(compressed) => compressed,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        let padded_data = match self.padding.pad(&compressed_data) {
            Ok(padded) => padded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        let aes_encrypted = match self.cipher.encrypt(CipherAlgorithm::Aes256Gcm, &padded_data) {
            Ok(aes_encrypted) => aes_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        let chacha_encrypted = match self.cipher.encrypt(CipherAlgorithm::XChaCha20Poly1305, &aes_encrypted) {
            Ok(chacha_encrypted) => chacha_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        let encoded_data = match self.encoder.encode(&chacha_encrypted) {
            Ok(encoded) => encoded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        let input_size = task.data.len();

        TaskResult::ok(task.index, encoded_data, input_size)
    }

    fn decrypt_pipeline(&self, task: &Task) -> TaskResult {
        let decoded_data = match self.encoder.decode(&task.data) {
            Ok(decoded) => decoded,
            Err(e) => return TaskResult::err(task.index, &e.context("decode")),
        };

        let chacha_decrypted = match self.cipher.decrypt(CipherAlgorithm::XChaCha20Poly1305, &decoded_data) {
            Ok(chacha_decrypted) => chacha_decrypted,
            Err(e) => return TaskResult::err(task.index, &e.context("chacha20poly1305 decrypt")),
        };

        let aes_decrypted = match self.cipher.decrypt(CipherAlgorithm::Aes256Gcm, &chacha_decrypted) {
            Ok(aes_decrypted) => aes_decrypted,
            Err(e) => {
                return TaskResult::err(task.index, &e.context("aes256gcm decrypt"));
            }
        };

        let unpadded_data = match self.padding.unpad(&aes_decrypted) {
            Ok(unpadded) => unpadded,
            Err(e) => return TaskResult::err(task.index, &e.context("unpad")),
        };

        let decompressed_data = match Compressor::decompress(&unpadded_data) {
            Ok(decompressed) => decompressed,
            Err(e) => return TaskResult::err(task.index, &e.context("decompress")),
        };

        let output_size = decompressed_data.len();

        TaskResult::ok(task.index, decompressed_data, output_size)
    }
}
