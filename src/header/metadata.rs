use anyhow::{Context, Result, ensure};

use crate::config::MAX_FILENAME_LENGTH;

#[derive(Debug, Clone)]
pub struct FileMetadata {
    filename: String,

    size: u64,

    created_at: u64,

    modified_at: u64,
}

impl FileMetadata {
    pub fn new(filename: impl Into<String>, size: u64, created_at: u64, modified_at: u64) -> Self {
        let mut filename = filename.into();

        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        Self { filename, size, created_at, modified_at }
    }

    #[inline]
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    #[inline]
    #[must_use]
    pub const fn modified_at(&self) -> u64 {
        self.modified_at
    }

    pub fn serialize(&self) -> Vec<u8> {
        let filename_bytes = self.filename.as_bytes();
        let filename_len = filename_bytes.len() as u16;

        let total_size = 2 + filename_bytes.len() + 24;
        let mut data = Vec::with_capacity(total_size);

        data.extend_from_slice(&filename_len.to_be_bytes());

        data.extend_from_slice(filename_bytes);

        data.extend_from_slice(&self.size.to_be_bytes());

        data.extend_from_slice(&self.created_at.to_be_bytes());

        data.extend_from_slice(&self.modified_at.to_be_bytes());

        data
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 26, "metadata too short: expected at least 26 bytes, got {}", data.len());

        let filename_len = u16::from_be_bytes(data[0..2].try_into().context("filename length conversion")?);
        let filename_len = filename_len as usize;

        ensure!(filename_len <= MAX_FILENAME_LENGTH, "filename too long: {} bytes (max {})", filename_len, MAX_FILENAME_LENGTH);

        let required_len = 2 + filename_len + 24;
        ensure!(data.len() >= required_len, "metadata too short: expected {}, got {}", required_len, data.len());

        let filename_end = 2 + filename_len;
        let filename = std::str::from_utf8(&data[2..filename_end]).context("invalid UTF-8 in filename")?.to_string();

        let size = u64::from_be_bytes(data[filename_end..filename_end + 8].try_into().context("size conversion")?);

        let created_at = u64::from_be_bytes(data[filename_end + 8..filename_end + 16].try_into().context("created_at conversion")?);

        let modified_at = u64::from_be_bytes(data[filename_end + 16..filename_end + 24].try_into().context("modified_at conversion")?);

        Ok(Self { filename, size, created_at, modified_at })
    }
}
