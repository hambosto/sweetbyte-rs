use secrecy::{ExposeSecret, SecretString};

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
