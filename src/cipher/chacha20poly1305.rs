use anyhow::{Context, Result};
use ring::aead::{Aad, BoundKey, CHACHA20_POLY1305, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

use crate::secret::SecretBytes;

struct OneTimeNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0.take().map(Nonce::assume_unique_for_key).ok_or(Unspecified)
    }
}

pub struct ChaCha20Poly1305 {
    key: SecretBytes,
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(key.len() == CHACHA20_POLY1305.key_len(), "invalid key length");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "empty plaintext");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes).context("nonce generation failed")?;

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, self.key.expose_secret()).context("key setup failed")?;
        let mut sealing_key = SealingKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

        let mut buffer = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut buffer).context("encryption failed")?;

        let mut result = Vec::with_capacity(NONCE_LEN + buffer.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= NONCE_LEN, "ciphertext too short");

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_LEN);
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().context("invalid nonce")?;

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, self.key.expose_secret()).context("key setup failed")?;
        let mut opening_key = OpeningKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

        let mut buffer = ciphertext.to_vec();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut buffer).context("decryption failed")?;

        Ok(plaintext.to_vec())
    }
}
