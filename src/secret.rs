use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

pub(crate) struct Secret(SecretBox<Vec<u8>>);

impl Secret {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(data)))
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn expose_secret_mut(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut()
    }
}
