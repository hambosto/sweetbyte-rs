use std::marker::PhantomData;

use aead::{Aead, AeadCore, Generate, KeyInit, Nonce};
use anyhow::{Context, Result};
use hybrid_array::typenum::Unsigned;
use rand::rngs::SysRng;

use crate::core::{KeyBytes, Secret};

pub(crate) struct Cipher<T> {
    key: Secret,
    cipher: PhantomData<T>,
}

impl<T> Cipher<T>
where
    T: Aead + AeadCore + KeyInit,
{
    pub(crate) fn new(key: &Secret) -> Result<Self> {
        let key = KeyBytes::try_new(key.expose_secret().into()).context("key must be 32 bytes")?;

        Ok(Self { key: key.into(), cipher: PhantomData })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            anyhow::bail!("plaintext must not be empty");
        }

        let cipher = T::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        let nonce = Nonce::<T>::try_generate_from_rng(&mut SysRng).context("failed to generate nonce")?;
        let ciphertext = cipher.encrypt(&nonce, plaintext).context("failed to encrypt")?;

        let mut result = Vec::with_capacity(nonce.len().saturating_add(ciphertext.len()));
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            anyhow::bail!("ciphertext must not be empty");
        }

        let nonce_len = <T as AeadCore>::NonceSize::USIZE;
        if ciphertext.len() < nonce_len {
            anyhow::bail!("ciphertext too short for nonce");
        }

        let (nonce_bytes, body) = ciphertext.split_at(nonce_len);
        let nonce = Nonce::<T>::try_from(nonce_bytes).context("invalid nonce")?;
        let cipher = T::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        let plaintext = cipher.decrypt(&nonce, body).context("failed to decrypt")?;

        Ok(plaintext)
    }
}
