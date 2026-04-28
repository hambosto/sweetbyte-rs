use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::config::{SCRYPT_KEY_LEN, DATA_SHARDS, PARITY_SHARDS};
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
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let packed = shield.unpack(reader).await?;

        let (magic, version): (u32, u16) = postcard::from_bytes(&packed.params).context("failed to deserialize params")?;
        let (name, size, hash): (String, u64, Vec<u8>) = postcard::from_bytes(&packed.metadata).context("failed to deserialize metadata")?;
        let metadata = Metadata::new(name, size, hash)?;
        let params = Parameters::new(magic, version)?;

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
        let key_bytes = key.expose_secret();
        anyhow::ensure!(key_bytes.len() == SCRYPT_KEY_LEN, "invalid key length");

        let params_bytes = postcard::to_allocvec(&self.params).context("failed to serialize params")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("failed to serialize metadata")?;
        let signer = Signer::new(key_bytes).context("failed to create signer")?;

        Ok(signer.verify_parts(self.packed.mac.expose_secret(), &[self.packed.salt.expose_secret(), &params_bytes, &metadata_bytes]))
    }
}
