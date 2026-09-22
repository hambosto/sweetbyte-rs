use std::fmt::{Debug, Formatter, Result};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::KeyBytes;

pub(crate) struct Secret {
    boxed_secret: Box<[u8]>,
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.boxed_secret.as_mut().zeroize();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

impl From<Box<[u8]>> for Secret {
    fn from(source: Box<[u8]>) -> Self {
        Self::new(source)
    }
}

impl Secret {
    pub(crate) fn new(boxed_secret: Box<[u8]>) -> Self {
        Self { boxed_secret }
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        &self.boxed_secret
    }
}

impl Debug for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "SecretBox([REDACTED])")
    }
}

impl From<Vec<u8>> for Secret {
    fn from(secret: Vec<u8>) -> Self {
        Self::from(secret.into_boxed_slice())
    }
}

impl From<KeyBytes> for Secret {
    fn from(key: KeyBytes) -> Self {
        Self::from(key.into_inner())
    }
}
