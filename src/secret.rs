use secrecy::{ExposeSecret, SecretBox};

pub struct SecretBytes(SecretBox<Vec<u8>>);
pub struct SecretString(SecretBox<String>);

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(data)))
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl SecretString {
    pub fn new(data: impl Into<String>) -> Self {
        Self(SecretBox::new(Box::new(data.into())))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}
