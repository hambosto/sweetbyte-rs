use anyhow::{Context, Result};
use ring::aead::{Aad, BoundKey, CHACHA20_POLY1305, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub struct ChaCha20Poly1305 {
    key: Vec<u8>,
}

struct OneTimeNonce([u8; NONCE_LEN]);

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> std::result::Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> Result<Self> {
        UnboundKey::new(&CHACHA20_POLY1305, key).context("Invalid ChaCha20-Poly1305 key")?;

        Ok(Self { key: key.to_vec() })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes).context("Failed to generate nonce")?;

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key).context("Failed to create ChaCha20 key")?;
        let mut sealing_key = SealingKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut buffer = plaintext.to_vec();

        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut buffer).context("ChaCha20-Poly1305 encryption failed")?;

        let mut result = Vec::with_capacity(NONCE_LEN + buffer.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_LEN);
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().context("Invalid nonce length")?;

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key).context("Failed to create ChaCha20 key")?;
        let mut opening_key = OpeningKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut buf = ciphertext.to_vec();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut buf).context("ChaCha20-Poly1305 decryption failed")?;

        Ok(plaintext.to_vec())
    }
}
