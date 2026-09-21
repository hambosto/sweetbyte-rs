use std::marker::PhantomData;

use aead::{Aead, AeadCore, Generate, KeyInit, Nonce};
use anyhow::{Context, Result};
use hybrid_array::typenum::Unsigned;
use rand::rngs::SysRng;

use crate::core::{ExposeSecret, KeyBytes, Secret};

pub(crate) struct Cipher<T> {
    key: Secret,
    _marker: PhantomData<T>,
}

impl<T> Cipher<T>
where
    T: Aead + AeadCore + KeyInit,
{
    pub(crate) fn new(secret: &Secret) -> Result<Self> {
        let key = KeyBytes::try_new(secret.expose_secret().into()).context("invalid encryption key")?;

        Ok(Self { key: key.into(), _marker: PhantomData })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            anyhow::bail!("empty plaintext");
        }

        let cipher = T::new_from_slice(self.key.expose_secret()).context("failed to init cipher")?;
        let nonce = Nonce::<T>::try_generate_from_rng(&mut SysRng).context("failed to generate nonce")?;
        let ciphertext = cipher.encrypt(&nonce, plaintext).context("failed to encrypt data")?;

        let mut result = Vec::with_capacity(nonce.len().saturating_add(ciphertext.len()));
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            anyhow::bail!("empty ciphertext");
        }

        let nonce_len = <T as AeadCore>::NonceSize::USIZE;
        if ciphertext.len() < nonce_len {
            anyhow::bail!("ciphertext too short");
        }

        let (nonce_part, body) = ciphertext.split_at(nonce_len);
        let nonce = Nonce::<T>::try_from(nonce_part).context("invalid nonce")?;
        let cipher = T::new_from_slice(self.key.expose_secret()).context("failed to init cipher")?;
        let plaintext = cipher.decrypt(&nonce, body).context("failed to decrypt data")?;

        Ok(plaintext)
    }
}
