//! Common type definitions for SweetByte.
//!
//! Provides core enums and structures used throughout the application
//! for representing processing modes, tasks, and task results.
//!
//! # Overview
//!
//! - [`ProcessorMode`]: Distinguishes between encryption and decryption operations
//! - [`Processing`]: Wraps mode with display/label functionality
//! - [`Task`]: Represents a chunk of data to be processed
//! - [`TaskResult`]: Holds the result of processing a task

use std::fmt::{Display, Formatter, Result};

/// Represents the type of file operation to perform.
///
/// Used to filter files during discovery and determine output path generation.
#[derive(Clone, Copy, PartialEq)]
pub enum ProcessorMode {
    /// Encrypt the file, producing a `.swx` output.
    Encrypt,

    /// Decrypt the file, removing the `.swx` extension.
    Decrypt,
}

impl ProcessorMode {
    /// Array containing all processor modes for iteration.
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    /// Returns a human-readable label for the mode.
    ///
    /// Used in user-facing output and prompts.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    /// Formats the mode for user display.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Represents a processing operation in progress.
///
/// Provides display labels for progress indicators and logging.
#[derive(Clone, Copy)]
pub enum Processing {
    /// An encryption operation is in progress.
    Encryption,

    /// A decryption operation is in progress.
    Decryption,
}

impl Processing {
    /// Returns a progress label for the operation.
    ///
    /// Different from `ProcessorMode::label()` as it includes action context.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    /// Converts a `Processing` to its corresponding `ProcessorMode`.
    #[inline]
    pub fn mode(self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    /// Formats the processing state for display.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Represents a unit of work to be processed by the pipeline.
///
/// Tasks are created by the Reader module and processed
/// by the Executor module using the Pipeline.
pub struct Task {
    /// The data payload to process.
    pub data: Vec<u8>,

    /// Sequential index for ordering results.
    ///
    /// Used by the Writer module to ensure
    /// results are written in the correct order.
    pub index: u64,
}

/// Result of processing a [`Task`].
///
/// Contains either the processed data or an error message.
pub struct TaskResult {
    /// The processed data (empty if an error occurred).
    pub data: Vec<u8>,

    /// Error message if processing failed, `None` on success.
    pub error: Option<Box<str>>,

    /// The original task index for ordering.
    pub index: u64,

    /// Size of the original data in bytes.
    ///
    /// Used for progress tracking.
    pub size: usize,
}

impl TaskResult {
    /// Creates a successful task result.
    ///
    /// # Arguments
    ///
    /// * `index` - The task index.
    /// * `data` - The processed data.
    /// * `size` - The size of the original input data.
    #[inline]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    /// Creates a failed task result.
    ///
    /// # Arguments
    ///
    /// * `index` - The task index.
    /// * `error` - The error that occurred.
    #[inline]
    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}
