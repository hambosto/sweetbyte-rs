use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy)]
pub enum ProcessorMode {
    Encrypt,
    Decrypt,
}

impl ProcessorMode {
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Processing {
    Encryption,
    Decryption,
}

impl Processing {
    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    pub fn mode(self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
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
