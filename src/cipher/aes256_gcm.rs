use anyhow::{Context, Result};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::secret::Secret;
use crate::validation::{KeyBytes32, NonEmptyBytes};

pub(super) struct Aes256Gcm {
    key: Secret,
}

impl Aes256Gcm {
    pub fn new(key: &Secret) -> Result<Self> {
        let inner = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must be 32 bytes")?;

        Ok(Self { key: inner.into_secret() })
    }

    #[inline]
    pub(super) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = NonEmptyBytes::try_new(plaintext.to_vec()).context("plaintext must not be empty")?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes).context("failed to generate nonce")?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, self.key.expose_secret()).context("failed to setup key")?);

        let mut buffer = plaintext.as_ref().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer).context("failed to encrypt")?;

        let mut result = Vec::with_capacity(NONCE_LEN.saturating_add(buffer.len()));
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);

        Ok(result)
    }

    #[inline]
    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = NonEmptyBytes::try_new(ciphertext.to_vec()).context("ciphertext must not be empty")?;
        let (nonce_bytes, body) = ciphertext.as_ref().split_at(NONCE_LEN);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().context("invalid nonce")?);
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, self.key.expose_secret()).context("failed to setup key")?);

        let mut buffer = body.to_vec();
        let plaintext = key.open_in_place(nonce, Aad::empty(), &mut buffer).context("failed to decrypt")?;

        Ok(plaintext.to_vec())
    }
}
