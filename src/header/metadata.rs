use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::config::{HASH_SIZE, MAX_FILENAME_LENGTH};

#[derive(Clone, Serialize)]
pub struct FileMetadata {
    name: String,
    size: u64,
    hash: [u8; HASH_SIZE],
}

impl FileMetadata {
    const FILENAME_LEN_SIZE: usize = 2;
    const SIZE_FIELD_SIZE: usize = 8;
    const MIN_SERIALIZED_SIZE: usize = Self::FILENAME_LEN_SIZE + Self::SIZE_FIELD_SIZE + HASH_SIZE;

    pub fn new(filename: impl Into<String>, size: u64, content_hash: [u8; HASH_SIZE]) -> Self {
        let mut filename = filename.into();

        if filename.len() > MAX_FILENAME_LENGTH {
            filename.truncate(MAX_FILENAME_LENGTH);
        }

        Self { name: filename, size, hash: content_hash }
    }

    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    #[must_use]
    pub const fn hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }

    pub fn serialize(&self) -> Vec<u8> {
        let filename_bytes = self.name.as_bytes();
        let filename_len = filename_bytes.len() as u16;

        let total_size = Self::FILENAME_LEN_SIZE + filename_bytes.len() + Self::SIZE_FIELD_SIZE + HASH_SIZE;
        let mut data = Vec::with_capacity(total_size);

        data.extend_from_slice(&filename_len.to_be_bytes());
        data.extend_from_slice(filename_bytes);
        data.extend_from_slice(&self.size.to_be_bytes());
        data.extend_from_slice(&self.hash);

        data
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= Self::MIN_SERIALIZED_SIZE, "metadata too short: expected at least {} bytes, got {}", Self::MIN_SERIALIZED_SIZE, data.len());

        let filename_len = Self::read_filename_length(data)?;
        ensure!(filename_len <= MAX_FILENAME_LENGTH, "filename too long: {filename_len} bytes (max {MAX_FILENAME_LENGTH})");

        let required_len = Self::calculate_required_length(filename_len);
        ensure!(data.len() >= required_len, "metadata too short: expected {}, got {}", required_len, data.len());

        let filename = Self::read_filename(data, filename_len)?;
        let size = Self::read_size(data, filename_len)?;
        let content_hash = Self::read_content_hash(data, filename_len)?;

        Ok(Self { name: filename, size, hash: content_hash })
    }

    fn read_filename_length(data: &[u8]) -> Result<usize> {
        let bytes = data[0..Self::FILENAME_LEN_SIZE].try_into().context("filename length conversion")?;
        Ok(u16::from_be_bytes(bytes) as usize)
    }

    fn calculate_required_length(filename_len: usize) -> usize {
        Self::FILENAME_LEN_SIZE + filename_len + Self::SIZE_FIELD_SIZE + HASH_SIZE
    }

    fn read_filename(data: &[u8], filename_len: usize) -> Result<String> {
        let start = Self::FILENAME_LEN_SIZE;
        let end = start + filename_len;

        std::str::from_utf8(&data[start..end]).context("invalid UTF-8 in filename").map(|s| s.to_owned())
    }

    fn read_size(data: &[u8], filename_len: usize) -> Result<u64> {
        let start = Self::FILENAME_LEN_SIZE + filename_len;
        let end = start + Self::SIZE_FIELD_SIZE;

        let bytes = data[start..end].try_into().context("size conversion")?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_content_hash(data: &[u8], filename_len: usize) -> Result<[u8; HASH_SIZE]> {
        let start = Self::FILENAME_LEN_SIZE + filename_len + Self::SIZE_FIELD_SIZE;
        let end = start + HASH_SIZE;

        data[start..end].try_into().context("content hash conversion")
    }
}
