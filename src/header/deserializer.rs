use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::cipher::Signer;
use crate::codec::CompressionLevel;
use crate::config::{ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::{Section, SectionData};
use crate::secret::Secret;

pub(super) struct Deserializer {
    params: Parameters,
    metadata: Metadata,
    section_data: SectionData,
}

impl Deserializer {
    pub(super) async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let section: Section = Section::new(CompressionLevel::Best, ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize section encoder")?;
        let section_data: SectionData = section.unpack(reader).await.context("failed to unpack section data")?;
        let params: Parameters = postcard::from_bytes(section_data.params.expose_secret()).context("failed to deserialize params")?;
        let metadata: Metadata = postcard::from_bytes(section_data.metadata.expose_secret()).context("failed to deserialize metadata")?;

        Ok(Self { params, metadata, section_data })
    }

    pub(super) fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub(super) fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub(super) fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub(super) fn salt(&self) -> &Secret {
        &self.section_data.salt
    }

    pub(super) fn verify(&self, signer_key: &Secret) -> Result<bool> {
        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(signer_key).context("failed to create signer")?;

        Ok(signer.verify_parts(self.section_data.mac.expose_secret(), &[self.section_data.salt.expose_secret(), &params_bytes, &metadata_bytes]))
    }
}
