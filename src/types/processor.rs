use std::fmt;

/// Defines the operation mode for the processor.
///
/// This enum is used to configure the high-level intent of the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    /// Encrypts files.
    Encrypt,
    /// Decrypts files.
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

/// Describes the current processing state or action.
///
/// This is often used for logging, UI updates, or internal state tracking
/// to indicate what operation is currently being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Processing {
    /// The system is currently performing encryption.
    Encryption,
    /// The system is currently performing decryption.
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
