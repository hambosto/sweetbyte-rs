use secrecy::{ExposeSecret, SecretBox};

pub struct Secret(SecretBox<Vec<u8>>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(data)))
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}
