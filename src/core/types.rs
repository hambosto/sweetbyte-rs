use anyhow::{Context, Result};

use crate::config::{CURRENT_VERSION, KEY_LEN, MAGIC_BYTES, MAX_FILENAME_LEN};
use crate::core::secret::Secret;

#[nutype::nutype(validate(not_empty, len_char_max = MAX_FILENAME_LEN), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileSize(u64);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileHash(Vec<u8>);

#[nutype::nutype(validate(predicate = |&m| m == MAGIC_BYTES), derive(Serialize, Deserialize))]
pub(crate) struct Magic(u32);

#[nutype::nutype(validate(predicate = |&v| v == CURRENT_VERSION), derive(Serialize, Deserialize))]
pub(crate) struct Version(u16);

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub(crate) struct KeyBytes(Vec<u8>);

#[nutype::nutype(validate(predicate = |b| !b.is_empty()))]
pub(crate) struct NonEmptyKey(Vec<u8>);

impl KeyBytes {
    pub(crate) fn into_secret(self) -> Secret {
        Secret::new(self.into_inner())
    }
}

impl NonEmptyKey {
    pub(crate) fn into_secret(self) -> Secret {
        Secret::new(self.into_inner())
    }
}

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

pub(crate) struct Task {
    pub(crate) data: Vec<u8>,
    pub(crate) index: u64,
}

pub(crate) struct TaskResult {
    pub(crate) index: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) size: usize,
}

impl TaskResult {
    pub(crate) fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { index, data, size }
    }
}
