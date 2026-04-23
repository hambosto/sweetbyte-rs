use std::cmp::Ordering;
use std::path::Path;

use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, IntoStaticStr)]
pub enum Processing {
    #[strum(to_string = "Encrypt")]
    Encryption,
    #[strum(to_string = "Decrypt")]
    Decryption,
}

impl Processing {
    pub fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }
}

pub struct FileHeader {
    pub name: String,
    pub size: u64,
    pub hash: String,
}

pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

#[derive(PartialEq, Eq)]
pub struct TaskResult {
    pub index: u64,
    pub data: Vec<u8>,
    pub size: usize,
}

impl TaskResult {
    pub fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { index, data, size }
    }
}

impl Ord for TaskResult {
    fn cmp(&self, other: &Self) -> Ordering {
        other.index.cmp(&self.index)
    }
}

impl PartialOrd for TaskResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub trait PathName {
    fn name(&self) -> &str;
}

impl PathName for Path {
    fn name(&self) -> &str {
        self.file_name().and_then(|n| n.to_str()).unwrap_or_default()
    }
}
