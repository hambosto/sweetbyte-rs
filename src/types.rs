use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

#[derive(Clone, Copy, Display, EnumIter, IntoStaticStr)]
pub enum ProcessorMode {
    #[strum(to_string = "Encrypt")]
    Encrypt,
    #[strum(to_string = "Decrypt")]
    Decrypt,
}

impl ProcessorMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        self.into()
    }

    pub fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, IntoStaticStr)]
pub enum Processing {
    #[strum(to_string = "Encrypting...")]
    Encryption,
    #[strum(to_string = "Decrypting...")]
    Decryption,
}

impl Processing {
    #[must_use]
    pub fn label(self) -> &'static str {
        self.into()
    }
}

impl From<ProcessorMode> for Processing {
    fn from(mode: ProcessorMode) -> Self {
        match mode {
            ProcessorMode::Encrypt => Self::Encryption,
            ProcessorMode::Decrypt => Self::Decryption,
        }
    }
}

impl From<Processing> for ProcessorMode {
    fn from(processing: Processing) -> Self {
        match processing {
            Processing::Encryption => Self::Encrypt,
            Processing::Decryption => Self::Decrypt,
        }
    }
}

pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

pub struct TaskResult {
    pub data: Vec<u8>,
    pub error: Option<Box<str>>,
    pub index: u64,
    pub size: usize,
}

impl TaskResult {
    #[must_use]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    #[must_use]
    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}

pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
}
