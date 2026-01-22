use anyhow::{Result, ensure};

use crate::cipher::Mac;
use crate::config::{ARGON_SALT_LEN, CONTENT_HASH_SIZE, HEADER_DATA_SIZE, MAGIC_BYTES};
use crate::header::metadata::FileMetadata;
use crate::header::section::{EncodedSection, SectionEncoder, SectionType};

pub struct SerializeParams<'a> {
    pub version: u16,

    pub algorithm: u8,

    pub compression: u8,

    pub encoding: u8,

    pub kdf: u8,

    pub kdf_memory: u32,

    pub kdf_time: u8,

    pub kdf_parallelism: u8,

    pub metadata: &'a FileMetadata,

    pub content_hash: &'a [u8; CONTENT_HASH_SIZE],

    pub salt: &'a [u8],

    pub key: &'a [u8],
}

pub struct Serializer<'a> {
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    #[inline]
    #[must_use]
    pub const fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    pub fn serialize(&self, params: &SerializeParams<'_>) -> Result<Vec<u8>> {
        ensure!(params.salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, params.salt.len());
        ensure!(!params.key.is_empty(), "key cannot be empty");

        let magic = MAGIC_BYTES.to_be_bytes();

        let header_data = Self::serialize_header_data(params);

        let metadata_bytes = params.metadata.serialize();

        let mac = Mac::new(params.key)?.compute(&[&magic, params.salt, &header_data, &metadata_bytes, params.content_hash])?;

        let raw_sections: [&[u8]; 6] = [&magic, params.salt, &header_data, &metadata_bytes, params.content_hash, &mac];

        let sections = self.encode_all_sections(&raw_sections)?;

        let length_sections = self.encode_length_prefixes(&sections)?;

        let lengths_header = Self::build_lengths_header(&length_sections);

        Ok(Self::assemble(&lengths_header, &length_sections, &sections))
    }

    fn encode_all_sections(&self, raw: &[&[u8]; 6]) -> Result<[EncodedSection; 6]> {
        SectionType::ALL
            .iter()
            .map(|st| self.encoder.encode_section(raw[st.index()]))
            .collect::<Result<Vec<EncodedSection>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    fn encode_length_prefixes(&self, sections: &[EncodedSection; 6]) -> Result<[EncodedSection; 6]> {
        SectionType::ALL
            .iter()
            .map(|st| self.encoder.encode_length(sections[st.index()].length_u32()))
            .collect::<Result<Vec<EncodedSection>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    fn build_lengths_header(length_sections: &[EncodedSection; 6]) -> [u8; 24] {
        let mut header = [0u8; 24];
        for (i, section) in length_sections.iter().enumerate() {
            let offset = i * 4;
            header[offset..offset + 4].copy_from_slice(&section.length_u32().to_be_bytes());
        }
        header
    }

    fn assemble(lengths_header: &[u8], length_sections: &[EncodedSection; 6], data_sections: &[EncodedSection; 6]) -> Vec<u8> {
        let total_size = lengths_header.len() + length_sections.iter().map(|s| s.len()).sum::<usize>() + data_sections.iter().map(|s| s.len()).sum::<usize>();

        let mut result = Vec::with_capacity(total_size);

        result.extend_from_slice(lengths_header);

        for section in length_sections {
            result.extend_from_slice(section.data());
        }

        for section in data_sections {
            result.extend_from_slice(section.data());
        }

        result
    }

    #[inline]
    fn serialize_header_data(params: &SerializeParams<'_>) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];

        data[0..2].copy_from_slice(&params.version.to_be_bytes());

        data[2] = params.algorithm;

        data[3] = params.compression;

        data[4] = params.encoding;

        data[5] = params.kdf;

        data[6..10].copy_from_slice(&params.kdf_memory.to_be_bytes());

        data[10] = params.kdf_time;

        data[11] = params.kdf_parallelism;

        data
    }
}
