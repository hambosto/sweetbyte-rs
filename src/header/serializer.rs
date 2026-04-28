use anyhow::Result;

use crate::config::{CURRENT_VERSION, DATA_SHARDS, MAGIC_BYTES, PARITY_SHARDS, SCRYPT_KEY_LEN, SCRYPT_SALT_LEN};
use crate::core::Signer;
use crate::header::metadata::Metadata;
use crate::header::parameters::Parameters;
use crate::header::section::SectionShield;
use crate::secret::SecretBytes;

pub struct Serializer {
    params: Parameters,
    metadata: Metadata,
}

impl Serializer {
    pub fn new(metadata: Metadata) -> Result<Self> {
        let params = Parameters::new(MAGIC_BYTES, CURRENT_VERSION)?;

        Ok(Self { params, metadata })
    }

    pub fn file_hash(&self) -> &[u8] {
        self.metadata.hash()
    }

    pub fn serialize(&self, salt: &[u8], key: &SecretBytes) -> Result<Vec<u8>> {
        anyhow::ensure!(salt.len() == SCRYPT_SALT_LEN, "invalid salt length");
        anyhow::ensure!(key.expose_secret().len() == SCRYPT_KEY_LEN, "invalid key length");

        let params_bytes = postcard::to_allocvec(&self.params)?;
        let metadata_bytes = postcard::to_allocvec(&self.metadata)?;
        let mac = Signer::new(key.expose_secret())?.compute_parts(&[salt, &params_bytes, &metadata_bytes])?;
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;

        shield.pack(salt, &params_bytes, &metadata_bytes, &mac)
    }
}
