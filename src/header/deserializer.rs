use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::core::Signer;
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::{PackedSections, SectionShield};
use crate::secret::SecretBytes;

pub struct Deserializer {
    params: Parameters,
    metadata: Metadata,
    packed: PackedSections,
}

impl Deserializer {
    pub async fn deserialize<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS).context("failed to initialize shield")?;
        let packed = shield.unpack(reader).await.context("failed to unpack header sections")?;
        let params: Parameters = postcard::from_bytes(&packed.params).context("failed to deserialize params")?;
        let metadata: Metadata = postcard::from_bytes(&packed.metadata).context("failed to deserialize metadata")?;

        Ok(Self { params, metadata, packed })
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
        self.packed.salt.expose_secret()
    }

    pub fn verify(&self, key: &SecretBytes) -> Result<bool> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to deserialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to deserialize metadata")?;
        let signer = Signer::new(key).context("failed to create signer")?;

        Ok(signer.verify_parts(self.packed.mac.expose_secret(), &[self.packed.salt.expose_secret(), &params_bytes, &metadata_bytes]))
    }
}
