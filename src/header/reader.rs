use anyhow::{Context, Result};
use tokio::io::AsyncRead;

use crate::cipher::Signer;
use crate::config::{ARGON_KEY_LEN, DATA_SHARDS, PARITY_SHARDS};
use crate::header::section::{PackedSections, SectionShield};
use crate::header::types::{Metadata, Parameters};
use crate::secret::SecretBytes;

pub struct HeaderReader {
    params: Parameters,
    metadata: Metadata,
    packed: PackedSections,
}

impl HeaderReader {
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;
        let packed = shield.unpack(reader).await?;

        let (magic, version): (u32, u16) = postcard::from_bytes(&packed.params).context("Deserialize params")?;
        let (name, size, hash): (String, u64, Vec<u8>) = postcard::from_bytes(&packed.metadata).context("Deserialize metadata")?;
        let metadata = Metadata::new(name, size, hash)?;
        let params = Parameters::new(magic, version)?;

        Ok(Self { params, metadata, packed })
    }

    #[must_use] 
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    #[must_use] 
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    #[must_use] 
    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    #[must_use] 
    pub fn salt(&self) -> &[u8] {
        self.packed.salt.expose_secret()
    }

    pub fn verify(&self, key: &SecretBytes) -> Result<bool> {
        let key_bytes = key.expose_secret();
        anyhow::ensure!(key_bytes.len() == ARGON_KEY_LEN, "Invalid key length");

        let params_bytes = postcard::to_allocvec(&self.params).context("Serialize params failed")?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata).context("Serialize metadata failed")?;
        let signer = Signer::new(key_bytes).context("Create signer failed")?;

        Ok(signer.verify_parts(self.packed.mac.expose_secret(), &[self.packed.salt.expose_secret(), &params_bytes, &metadata_bytes]))
    }
}
