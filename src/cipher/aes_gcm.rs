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
        UnboundKey::new(&AES_256_GCM, key).context("invalid aes-gcm key")?;

        Ok(Self { key: key.to_vec() })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).context("failed to generate nonce")?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key).context("failed to create aes-gcm key")?;
        let mut sealing_key = SealingKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut buffer = plaintext.to_vec();

        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut buffer).context("failed to encrypt with aes-gcm")?;

        let mut result = Vec::with_capacity(NONCE_LEN + buffer.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_LEN);
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().context("invalid nonce length")?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key).context("failed to create aes-gcm key")?;
        let mut opening_key = OpeningKey::new(unbound, OneTimeNonce(nonce_bytes));
        let mut buffer = ciphertext.to_vec();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut buffer).context("failed to decrypt with aes-gcm")?;

        Ok(plaintext.to_vec())
    }
}
