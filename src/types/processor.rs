use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    Encrypt,
    Decrypt,
}

impl fmt::Display for ProcessorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessorMode::Encrypt => write!(f, "Encrypt"),
            ProcessorMode::Decrypt => write!(f, "Decrypt"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Processing {
    Encryption,
    Decryption,
}

impl fmt::Display for Processing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Processing::Encryption => write!(f, "Encrypting..."),
            Processing::Decryption => write!(f, "Decrypting..."),
        }
    }
}
