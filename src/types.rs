use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

#[non_exhaustive]
#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, IntoStaticStr)]
pub(crate) enum Processing {
    #[strum(to_string = "Encrypt")]
    Encryption,
    #[strum(to_string = "Decrypt")]
    Decryption,
}

impl Processing {
    pub(crate) fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    pub(crate) fn is_encryption(self) -> bool {
        matches!(self, Self::Encryption)
    }
}

pub(crate) struct FileHeader {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) hash: String,
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
