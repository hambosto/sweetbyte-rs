use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, IntoStaticStr)]
pub enum ProcessorMode {
    #[strum(to_string = "Encrypt")]
    Encryption,
    #[strum(to_string = "Decrypt")]
    Decryption,
}

impl ProcessorMode {
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

pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

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

pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
}
