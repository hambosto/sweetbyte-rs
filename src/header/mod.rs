mod deserializer;
mod metadata;
mod parameters;
mod section;
mod serializer;

use anyhow::{Context, Result};
use deserializer::Deserializer;
use serializer::Serializer;
use tokio::io::AsyncRead;

use crate::secret::Secret;

pub(crate) struct ReadHeader {
    deserializer: Deserializer,
}

impl ReadHeader {
    pub(crate) async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let deserializer = Deserializer::from_reader(reader).await.context("failed to read header")?;

        Ok(Self { deserializer })
    }

    pub(crate) fn name(&self) -> &str {
        self.deserializer.file_name()
    }

    pub(crate) fn size(&self) -> u64 {
        self.deserializer.file_size()
    }

    pub(crate) fn hash(&self) -> &[u8] {
        self.deserializer.file_hash()
    }

    pub(crate) fn salt(&self) -> &Secret {
        self.deserializer.salt()
    }

    pub(crate) fn verify(&self, signer_key: &Secret) -> Result<bool> {
        self.deserializer.verify(signer_key)
    }
}

pub(crate) struct WriteHeader {
    serializer: Serializer,
}

impl WriteHeader {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let serializer = Serializer::new(name, size, hash).context("failed to create header serializer")?;

        Ok(Self { serializer })
    }

    pub(crate) fn name(&self) -> &str {
        self.serializer.file_name()
    }

    pub(crate) fn size(&self) -> u64 {
        self.serializer.file_size()
    }

    pub(crate) fn hash(&self) -> &[u8] {
        self.serializer.file_hash()
    }

    pub(crate) fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        self.serializer.serialize(salt, signer_key)
    }
}
