use secrecy::{ExposeSecret, SecretBox, SecretString};

pub struct SecretBytes {
    inner: SecretBox<Vec<u8>>,
}

impl SecretBytes {
    pub fn new(data: &[u8]) -> Self {
        Self { inner: SecretBox::new(Box::new(data.to_vec())) }
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { inner: SecretBox::new(Box::new(data)) }
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }
}

impl From<SecretBox<Vec<u8>>> for SecretBytes {
    fn from(secret: SecretBox<Vec<u8>>) -> Self {
        Self { inner: secret }
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([... {} bytes ...])", self.inner.expose_secret().len())
    }
}

pub struct Secret {
    inner: SecretString,
}

impl Secret {
    pub fn new(password: &str) -> Self {
        Self { inner: SecretString::from(password.to_owned()) }
    }

    pub fn from_string(password: String) -> Self {
        Self { inner: SecretString::from(password) }
    }

    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
}

impl From<SecretString> for Secret {
    fn from(secret: SecretString) -> Self {
        Self { inner: secret }
    }
}
