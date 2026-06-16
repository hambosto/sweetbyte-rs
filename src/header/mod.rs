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

pub(crate) struct WriteHeader(Serializer);

impl WriteHeader {
    #[inline]
    #[must_use]
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        Serializer::new(name, size, hash).context("failed to create header serializer").map(Self)
    }

    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.0.file_name()
    }
    #[inline]
    pub(crate) fn size(&self) -> u64 {
        self.0.file_size()
    }
    #[inline]
    pub(crate) fn hash(&self) -> &[u8] {
        self.0.file_hash()
    }

    #[inline]
    pub(crate) fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        self.0.serialize(salt, signer_key)
    }
}

pub(crate) struct ReadHeader(Deserializer);

impl ReadHeader {
    #[inline]
    #[must_use]
    pub(crate) async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        Deserializer::from_reader(reader).await.context("failed to read header").map(Self)
    }

    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.0.file_name()
    }

    #[inline]
    pub(crate) fn size(&self) -> u64 {
        self.0.file_size()
    }

    #[inline]
    pub(crate) fn hash(&self) -> &[u8] {
        self.0.file_hash()
    }

    #[inline]
    pub(crate) fn salt(&self) -> &Secret {
        self.0.salt()
    }

    #[inline]
    pub(crate) fn verify(&self, signer_key: &Secret) -> Result<bool> {
        self.0.verify(signer_key)
    }
}
