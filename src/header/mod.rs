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

enum State {
    Write(Serializer),
    Read(Deserializer),
}

pub(crate) struct Header {
    state: State,
}

impl Header {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let serializer = Serializer::new(name, size, hash).context("failed to create serializer")?;

        Ok(Self { state: State::Write(serializer) })
    }

    pub(crate) async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let deserializer = Deserializer::from_reader(reader).await.context("failed to deserialize header")?;

        Ok(Self { state: State::Read(deserializer) })
    }

    pub(crate) fn serialize(&self, salt: &[u8], signer_key: &Secret) -> Result<Vec<u8>> {
        match &self.state {
            State::Write(s) => s.serialize(salt, signer_key),
            State::Read(_) => anyhow::bail!("failed to serialize header in read state"),
        }
    }

    pub(crate) fn verify(&self, signer_key: &Secret) -> Result<bool> {
        match &self.state {
            State::Read(d) => d.verify(signer_key),
            State::Write(_) => anyhow::bail!("failed to verify header in write state"),
        }
    }

    #[inline]
    pub(crate) fn file_name(&self) -> &str {
        match &self.state {
            State::Write(s) => s.file_name(),
            State::Read(d) => d.file_name(),
        }
    }

    #[inline]
    pub(crate) fn file_size(&self) -> u64 {
        match &self.state {
            State::Write(s) => s.file_size(),
            State::Read(d) => d.file_size(),
        }
    }

    #[inline]
    pub(crate) fn file_hash(&self) -> &[u8] {
        match &self.state {
            State::Write(s) => s.file_hash(),
            State::Read(d) => d.file_hash(),
        }
    }

    #[inline]
    pub(crate) fn salt(&self) -> Result<&Secret> {
        match &self.state {
            State::Read(d) => Ok(d.salt()),
            State::Write(_) => anyhow::bail!("failed to get salt from header in write state"),
        }
    }
}
