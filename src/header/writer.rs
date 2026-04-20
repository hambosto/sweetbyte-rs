use anyhow::Result;

use crate::cipher::Signer;
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN, CURRENT_VERSION, DATA_SHARDS, MAGIC_BYTES, PARITY_SHARDS};
use crate::header::section::SectionShield;
use crate::header::types::{Metadata, Parameters};
use crate::secret::SecretBytes;

pub struct HeaderWriter {
    params: Parameters,
    metadata: Metadata,
}

impl HeaderWriter {
    pub fn new(metadata: Metadata) -> Result<Self> {
        let params = Parameters::new(MAGIC_BYTES, CURRENT_VERSION)?;

        Ok(Self { params, metadata })
    }

    #[must_use]
    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn serialize(&self, salt: &[u8], key: &SecretBytes) -> Result<Vec<u8>> {
        anyhow::ensure!(salt.len() == ARGON_SALT_LEN, "Invalid salt len");
        anyhow::ensure!(key.expose_secret().len() == ARGON_KEY_LEN, "Invalid key len");

        let params_bytes = postcard::to_allocvec(&self.params)?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata)?;
        let mac = Signer::new(key.expose_secret())?.compute_parts(&[salt, &params_bytes, &metadata_bytes]);
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;

        shield.pack(salt, &params_bytes, &metadata_bytes, &mac)
    }
}
