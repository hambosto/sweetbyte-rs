use std::io::Read;

use anyhow::{Result, anyhow};

use crate::header::HeaderParameter;
use crate::header::metadata::FileMetadata;
use crate::header::section::{SectionDecoder, SectionType, Sections};

pub struct HeaderData {
    parameter: HeaderParameter,

    metadata: FileMetadata,

    sections: Sections,
}

impl HeaderData {
    #[inline]
    #[must_use]
    pub const fn parameters(&self) -> &HeaderParameter {
        &self.parameter
    }

    #[inline]
    #[must_use]
    pub const fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    #[inline]
    pub fn into_sections(self) -> Sections {
        self.sections
    }
}

pub struct Deserializer<'a> {
    decoder: &'a SectionDecoder,
}

impl<'a> Deserializer<'a> {
    #[inline]
    #[must_use]
    pub fn new(decoder: &'a SectionDecoder) -> Self {
        Self { decoder }
    }

    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<HeaderData> {
        let length_sizes = self.decoder.read_lengths_header(&mut reader)?;
        let section_lengths = self.decoder.read_and_decode_lengths(&mut reader, &length_sizes)?;
        let sections = self.decoder.read_and_decode_sections(&mut reader, &section_lengths)?;

        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow!("HeaderData section not found"))?;
        let parameter = HeaderParameter::deserialize(header_data)?;

        let metadata_bytes = sections.get(SectionType::Metadata).ok_or_else(|| anyhow!("Metadata section not found"))?;
        let metadata = FileMetadata::deserialize(metadata_bytes)?;

        Ok(HeaderData { parameter, metadata, sections })
    }
}
