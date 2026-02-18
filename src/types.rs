use strum::{Display, EnumIter, IntoStaticStr};

#[derive(Clone, Copy, Display, EnumIter, IntoStaticStr)]
pub enum ProcessorMode {
    #[strum(to_string = "Encrypt")]
    Encrypt,
    #[strum(to_string = "Decrypt")]
    Decrypt,
}

impl ProcessorMode {
    pub fn label(self) -> &'static str {
        self.into()
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
    pub fn label(self) -> &'static str {
        self.into()
    }

    pub fn mode(self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
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
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}
