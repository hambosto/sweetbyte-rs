use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    pub fn new(data: T) -> Self {
        Self { inner: data }
    }

    pub fn expose_secret(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize + ZeroizeOnDrop> ZeroizeOnDrop for Secret<T> {}

pub type SecretBytes = Secret<Vec<u8>>;
pub type SecretString = Secret<String>;
