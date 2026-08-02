use anyhow::{Context, Result};

use crate::config::MAX_FILENAME_LEN;

#[nutype::nutype(validate(not_empty, len_char_max = MAX_FILENAME_LEN), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileSize(u64);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileHash(Vec<u8>);

pub(crate) struct FileMetadata {
    pub(crate) name: Filename,
    pub(crate) size: FileSize,
    pub(crate) hash: FileHash,
}

impl FileMetadata {
    pub(crate) fn new(name: impl Into<String>, size: u64, hash: Vec<u8>) -> Result<Self> {
        let name = Filename::try_new(name.into()).context("invalid filename")?;
        let size = FileSize::try_new(size).context("invalid file size")?;
        let hash = FileHash::try_new(hash).context("invalid file hash")?;

        Ok(Self { name, size, hash })
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn size(&self) -> u64 {
        *self.size.as_ref()
    }

    pub(crate) fn hash(&self) -> &[u8] {
        self.hash.as_ref()
    }
}
