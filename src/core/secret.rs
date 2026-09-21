use std::fmt::{Debug, Formatter, Result};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::KeyBytes;

pub(crate) trait ExposeSecret<S: ?Sized> {
    fn expose_secret(&self) -> &S;
}

pub(crate) struct SecretBox<S: Zeroize + ?Sized> {
    boxed_secret: Box<S>,
}

impl<S: Zeroize + ?Sized> SecretBox<S> {
    pub(crate) fn new(boxed_secret: Box<S>) -> Self {
        Self { boxed_secret }
    }
}

impl<S: Zeroize + ?Sized> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&self) -> &S {
        self.boxed_secret.as_ref()
    }
}

impl<S: Zeroize + ?Sized> Zeroize for SecretBox<S> {
    fn zeroize(&mut self) {
        self.boxed_secret.as_mut().zeroize();
    }
}

impl<S: Zeroize + ?Sized> Drop for SecretBox<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S: Zeroize + ?Sized> ZeroizeOnDrop for SecretBox<S> {}

impl<S: Zeroize + ?Sized> Debug for SecretBox<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "[REDACTED]")
    }
}

pub(crate) struct Secret {
    secret: SecretBox<Vec<u8>>,
}

impl Secret {
    pub(crate) fn new(secret: Vec<u8>) -> Self {
        Self { secret: SecretBox::new(Box::new(secret)) }
    }
}

impl ExposeSecret<[u8]> for Secret {
    fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret()
    }
}

impl From<KeyBytes> for Secret {
    fn from(key: KeyBytes) -> Self {
        Secret::new(key.into_inner())
    }
}
