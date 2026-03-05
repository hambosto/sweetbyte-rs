use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::cipher::Signer;
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN, CURRENT_VERSION, DATA_SHARDS, MAGIC_BYTES, MAX_FILENAME_LENGTH, PARITY_SHARDS};
use crate::header::metadata::Metadata;
use crate::header::parameter::Parameters;
use crate::header::section::{DecodedSections, SectionShield};
use crate::secret::SecretBytes;

pub mod metadata;
pub mod parameter;
pub mod section;

pub struct Header {
    shield: SectionShield,
    parameters: Parameters,
    metadata: Metadata,
    sections: Option<DecodedSections>,
}

impl Header {
    pub fn new(metadata: Metadata) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let parameters = Parameters { magic: MAGIC_BYTES, version: CURRENT_VERSION };

        Self::with_parameters(shield, parameters, metadata)
    }

    pub fn with_parameters(shield: SectionShield, parameters: Parameters, metadata: Metadata) -> Result<Self> {
        anyhow::ensure!(parameters.validate(), "Invalid header parameters");
        anyhow::ensure!(metadata.size() > 0, "Cannot process zero-size file");

        Ok(Self { shield, parameters, metadata, sections: None })
    }

    pub async fn deserialize<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let sections = shield.unpack(&mut reader).await?;
        let params: Parameters = wincode::deserialize(&sections.parameter)?;
        let metadata: Metadata = wincode::deserialize(&sections.metadata)?;

        anyhow::ensure!(params.validate(), "Invalid header parameters");
        anyhow::ensure!(metadata.size() > 0, "Cannot process zero-size file");
        anyhow::ensure!(metadata.name().len() <= MAX_FILENAME_LENGTH, "Filename exceeds maximum allowed length ({MAX_FILENAME_LENGTH} bytes)");

        Ok(Self { shield, parameters: params, metadata, sections: Some(sections) })
    }

    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    pub const fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn salt(&self) -> Result<&[u8]> {
        self.sections.as_ref().map(|s| s.salt.expose_secret().as_slice()).context("Header has not been deserialized")
    }

    pub fn serialize(&self, salt: &[u8], key: &SecretBytes) -> Result<Vec<u8>> {
        anyhow::ensure!(salt.len() == ARGON_SALT_LEN, "Invalid salt length: expected {} bytes, got {}", ARGON_SALT_LEN, salt.len());
        anyhow::ensure!(key.expose_secret().len() == ARGON_KEY_LEN, "Invalid key length: expected {} bytes, got {}", ARGON_KEY_LEN, key.expose_secret().len());

        let parameter = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;
        let mac = Signer::new(key.expose_secret())?.compute_parts(&[salt, &parameter, &metadata_bytes])?;

        self.shield.pack(salt, &parameter, &metadata_bytes, &mac)
    }

    pub fn verify(&self, key: &SecretBytes) -> bool {
        if key.expose_secret().len() != ARGON_KEY_LEN {
            tracing::error!("Invalid key length: expected {} bytes, got {}", ARGON_KEY_LEN, key.expose_secret().len());
            return false;
        }

        let Some(sections) = &self.sections else {
            tracing::error!("Header has not been deserialized");
            return false;
        };

        let Ok(parameter_bytes) = wincode::serialize(&self.parameters) else {
            tracing::error!("Failed to serialize header parameters");
            return false;
        };

        let Ok(metadata_bytes) = wincode::serialize(&self.metadata) else {
            tracing::error!("Failed to serialize header metadata");
            return false;
        };

        let Ok(signer) = Signer::new(key.expose_secret()) else {
            tracing::error!("Failed to create cryptographic signer");
            return false;
        };

        signer.verify_parts(sections.mac.expose_secret(), &[sections.salt.expose_secret(), &parameter_bytes, &metadata_bytes])
    }
}
