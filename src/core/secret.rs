use secrecy::{ExposeSecret, SecretBox};

pub(crate) struct Secret {
    secret: SecretBox<Vec<u8>>,
}

impl Secret {
    pub(crate) fn new(secret: Vec<u8>) -> Self {
        Self { secret: SecretBox::new(Box::new(secret)) }
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret()
    }
}
