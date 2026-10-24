use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use super::section::Section;
use crate::config::{COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::{DecodedSection, Metadata, Parameters, Secret};
use crate::crypto::Signer;

pub(crate) struct Deserializer {
    parameters: Parameters,
    metadata: Metadata,
    decoded_section: DecodedSection,
}

impl Deserializer {
    pub(crate) async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let section: Section = Section::new(COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to init header encoder")?;
        let decoded_section: DecodedSection = section.unpack(reader).await.context("failed to unpack header")?;
        let parameters: Parameters = postcard::from_bytes(decoded_section.parameters.expose_secret()).context("failed to parse header parameters")?;
        let metadata: Metadata = postcard::from_bytes(decoded_section.metadata.expose_secret()).context("failed to parse header metadata")?;

        Ok(Self { parameters, metadata, decoded_section })
    }

    pub(crate) fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub(crate) fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub(crate) fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub(crate) fn salt(&self) -> &Secret {
        &self.decoded_section.salt
    }

    pub(crate) fn verify_mac(&self, signer_key: &Secret) -> Result<bool> {
        let encoded_parameters = postcard::to_allocvec(&self.parameters).context("failed to encode header parameters")?;
        let encoded_metadata = postcard::to_allocvec(&self.metadata).context("failed to encode header metadata")?;
        let signer = Signer::new(signer_key).context("failed to init auth signer")?;

        Ok(signer.verify_parts(self.decoded_section.mac.expose_secret(), &[self.decoded_section.salt.expose_secret(), &encoded_parameters, &encoded_metadata]))
    }
}
