use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::config::{ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::Signer;
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::{Header, Section};
use crate::secret::SecretBytes;

pub struct Deserializer {
    params: Parameters,
    metadata: Metadata,
    header: Header,
}

impl Deserializer {
    pub async fn deserialize<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let section = Section::new(ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize section encoder")?;
        let header = section.unpack(reader).await.context("failed to unpack header sections")?;
        let params: Parameters = postcard::from_bytes(header.params.expose_secret()).context("failed to deserialize params")?;
        let metadata: Metadata = postcard::from_bytes(header.metadata.expose_secret()).context("failed to deserialize metadata")?;

        Ok(Self { params, metadata, header })
    }

    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn salt(&self) -> &[u8] {
        self.header.salt.expose_secret()
    }

    pub fn verify(&self, signer_key: &SecretBytes) -> Result<bool> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(signer_key).context("failed to create signer")?;

        Ok(signer.verify_parts(self.header.mac.expose_secret(), &[self.header.salt.expose_secret(), &params_bytes, &metadata_bytes]))
    }
}
