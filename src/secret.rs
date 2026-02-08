use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretBox};

pub struct Secret<T: Zeroize> {
    inner: SecretBox<T>,
}

impl<T: Zeroize> Secret<T> {
    pub fn new(data: T) -> Self {
        Self { inner: SecretBox::new(Box::new(data)) }
    }

    pub fn expose_secret(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> From<SecretBox<T>> for Secret<T> {
    fn from(secret: SecretBox<T>) -> Self {
        Self { inner: secret }
    }
}

pub type SecretBytes = Secret<Vec<u8>>;
pub type SecretString = Secret<String>;

impl SecretBytes {
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl SecretString {
    pub fn from_str(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}
