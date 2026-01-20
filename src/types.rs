use std::fmt::{Display, Formatter, Result};

/// Represents the processing mode for files.
///
/// This enum distinguishes between encryption and decryption operations,
/// which determines the direction of data transformation and file filtering logic.
#[derive(Clone, Copy, PartialEq)]
pub enum ProcessorMode {
    /// Mode for encrypting unencrypted files.
    Encrypt,
    /// Mode for decrypting encrypted files.
    Decrypt,
}

impl ProcessorMode {
    /// Array containing all available processor modes for iteration.
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    /// Returns a human-readable label for the mode.
    ///
    /// Returns "Encrypt" for encryption mode and "Decrypt" for decryption mode.
    ///
    /// # Returns
    /// A static string slice representing the mode name.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    /// Formats the processor mode for display purposes.
    ///
    /// Delegates to `label()` to produce the string representation.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Represents the processing operation type.
///
/// This enum describes whether encryption or decryption is being performed,
/// controlling the user-facing labels and processor mode selection.
#[derive(Clone, Copy)]
pub enum Processing {
    /// Indicates an encryption operation.
    Encryption,
    /// Indicates a decryption operation.
    Decryption,
}

impl Processing {
    /// Returns a human-readable label for the processing operation.
    ///
    /// Returns "Encrypting..." for encryption operations and "Decrypting..."
    /// for decryption operations, suitable for progress display.
    ///
    /// # Returns
    /// A static string slice representing the operation label.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    /// Converts the processing operation to its corresponding processor mode.
    ///
    /// Encryption maps to `ProcessorMode::Encrypt` and decryption maps to
    /// `ProcessorMode::Decrypt`.
    ///
    /// # Returns
    /// The corresponding `ProcessorMode` for this processing operation.
    pub fn mode(self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    /// Formats the processing operation for display purposes.
    ///
    /// Uses the label() method to produce the string representation.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Represents a single task for parallel processing.
///
/// A task contains a chunk of data to be processed along with its sequential
/// index for result ordering. Tasks are created by the Reader and processed
/// by the Executor in the worker pipeline.
pub struct Task {
    /// The data payload to be processed (encrypted or decrypted).
    pub data: Vec<u8>,
    /// The sequential index of this task for result ordering.
    /// Lower indices represent earlier chunks in the file.
    pub index: u64,
}

/// Represents the result of processing a task.
///
/// Contains either the successfully processed data or an error message,
/// along with metadata for progress tracking and result ordering.
pub struct TaskResult {
    /// The processed data payload. Empty if an error occurred.
    pub data: Vec<u8>,
    /// Optional error message if processing failed.
    /// None indicates successful processing.
    pub error: Option<Box<str>>,
    /// The sequential index matching the original Task, for result ordering.
    pub index: u64,
    /// The size of the original input data for this task, for progress tracking.
    pub size: usize,
}

impl TaskResult {
    /// Creates a successful task result.
    ///
    /// # Arguments
    /// * `index` - The sequential index of the original task.
    /// * `data` - The processed data payload.
    /// * `size` - The size of the original input data.
    ///
    /// # Returns
    /// A TaskResult with no error, containing the processed data.
    #[inline]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    /// Creates an error task result.
    ///
    /// # Arguments
    /// * `index` - The sequential index of the original task.
    /// * `error` - The error that occurred during processing.
    ///
    /// # Returns
    /// A TaskResult with an error message and empty data.
    #[inline]
    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}
