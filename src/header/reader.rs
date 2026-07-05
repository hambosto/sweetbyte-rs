use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use super::deserializer::Deserializer;
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
