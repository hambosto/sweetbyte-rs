use anyhow::{Context, Result};
use ring::aead::{AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub struct AesGcm {
    key: Vec<u8>,
}

struct OneTimeNonce([u8; NONCE_LEN]);

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Result<Self> {
        UnboundKey::new(&AES_256_GCM, key).context("Invalid AES-256-GCM key")?;

        Ok(Self { key: key.to_vec() })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "Cannot encrypt empty plaintext");

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).context("Failed to generate nonce")?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key).context("Failed to create AES key")?;
        let mut sealing_key = SealingKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut ciphertext = plaintext.to_vec();

        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut ciphertext).context("AES-GCM encryption failed")?;

        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= NONCE_LEN, "Ciphertext too short (minimum {NONCE_LEN} bytes required)");

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_LEN);
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().context("Invalid nonce length")?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key).context("Failed to create AES key")?;
        let mut opening_key = OpeningKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut buffer = ciphertext.to_vec();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut buffer).context("AES-GCM decryption failed")?;

        Ok(plaintext.to_vec())
    }
}
