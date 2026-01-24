use anyhow::{Result, ensure};

use crate::cipher::Mac;
use crate::config::{ARGON_SALT_LEN, MAGIC_BYTES};
use crate::header::metadata::FileMetadata;
use crate::header::parameter::Params;
use crate::header::section::SectionEncoder;

pub struct SerializeParameter<'a> {
    pub params: Params,

    pub metadata: &'a FileMetadata,

    pub salt: &'a [u8],

    pub key: &'a [u8],
}

pub struct Serializer<'a> {
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    #[inline]
    #[must_use]
    pub fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    pub fn serialize(&self, params: &SerializeParameter<'_>) -> Result<Vec<u8>> {
        ensure!(params.salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, params.salt.len());
        ensure!(!params.key.is_empty(), "key cannot be empty");

        let magic = MAGIC_BYTES.to_be_bytes();
        let header_data = params.params.serialize();
        let metadata_bytes = params.metadata.serialize();
        let mac = Mac::new(params.key)?.compute(&[&magic, params.salt, &header_data, &metadata_bytes])?;

        let raw_sections: [&[u8]; 5] = [&magic, params.salt, &header_data, &metadata_bytes, &mac];
        let (sections, length_sections) = self.encoder.encode_sections_and_lengths(&raw_sections)?;
        let lengths_header = SectionEncoder::build_lengths_header(&length_sections);

        let result: Vec<u8> = lengths_header
            .iter()
            .cloned()
            .chain(length_sections.iter().flat_map(|s| s.data().iter().cloned()))
            .chain(sections.iter().flat_map(|s| s.data().iter().cloned()))
            .collect();

        Ok(result)
    }
}
