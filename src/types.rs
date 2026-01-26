//! Core type definitions and data structures.
//!
//! This module defines the fundamental types used throughout the application to represent:
//! - Processing modes (Encrypt vs Decrypt)
//! - Unit of work (Tasks)
//! - Results of processing (TaskResult)
//!
//! These types serve as the common language between the CLI, the worker pipeline,
//! and the UI components.

use std::fmt::{Display, Formatter, Result};

/// Represents the high-level operation mode of the application.
///
/// This enum is used to distinguish between the two primary functions of SweetByte:
/// encryption and decryption.
///
/// # Examples
///
/// ```
/// use sweetbyte_rs::types::ProcessorMode;
///
/// let mode = ProcessorMode::Encrypt;
/// assert_eq!(mode.label(), "Encrypt");
/// ```
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub enum ProcessorMode {
    /// Mode for encrypting files.
    Encrypt,

    /// Mode for decrypting files.
    Decrypt,
}

impl ProcessorMode {
    /// A slice containing all available processor modes.
    ///
    /// Useful for iteration or validation logic that needs to check against
    /// all possible states.
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    /// Returns a human-readable string label for the mode.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::types::ProcessorMode;
    ///
    /// assert_eq!(ProcessorMode::Encrypt.label(), "Encrypt");
    /// ```
    #[inline]
    pub fn label(self) -> &'static str {
        // Match on self to return the corresponding static string literal.
        // This is a simple mapping from enum variant to display text.
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    /// Formats the mode using its label.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        // Delegate to the label() method to get the string representation.
        // This ensures consistency between explicit label access and Display formatting.
        f.write_str(self.label())
    }
}

/// Represents the continuous state of processing.
///
/// Unlike [`ProcessorMode`] which represents the *intent* or configuration,
/// `Processing` represents the *active action* (e.g., "Encrypting..." vs "Encrypt").
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Processing {
    /// State when encryption is in progress.
    Encryption,

    /// State when decryption is in progress.
    Decryption,
}

impl Processing {
    /// Returns a human-readable string description of the active process.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::types::Processing;
    ///
    /// assert_eq!(Processing::Encryption.label(), "Encrypting...");
    /// ```
    #[inline]
    pub fn label(self) -> &'static str {
        // Map the processing state to a progressive verb string.
        // Used primarily for UI feedback during long-running operations.
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    /// Converts the processing state back to its corresponding [`ProcessorMode`].
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::types::{Processing, ProcessorMode};
    ///
    /// assert_eq!(Processing::Encryption.mode(), ProcessorMode::Encrypt);
    /// ```
    #[inline]
    pub fn mode(self) -> ProcessorMode {
        // Map the active processing state back to the configuration mode.
        // This is useful when the UI needs to switch context based on current activity.
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    /// Formats the processing state using its label.
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        // Write the progressive verb label to the formatter.
        // This allows using the enum directly in format! macros.
        f.write_str(self.label())
    }
}

/// A unit of work to be processed by the worker pipeline.
///
/// Tasks are created by the reader, processed by the executor, and finalized
/// by the writer. Each task represents a chunk of file data.
pub struct Task {
    /// The raw data payload to be processed.
    pub data: Vec<u8>,

    /// The sequential index of this chunk (0-based).
    /// Used to maintain order during parallel processing and reassembly.
    pub index: u64,
}

/// The result of processing a [`Task`].
///
/// Contains the processed data (encrypted or decrypted) or an error if the
/// operation failed.
pub struct TaskResult {
    /// The processed data payload.
    /// Empty if an error occurred.
    pub data: Vec<u8>,

    /// The error message if processing failed, or `None` on success.
    pub error: Option<Box<str>>,

    /// The sequential index of the chunk, corresponding to the input [`Task`].
    pub index: u64,

    /// The size of the useful data in bytes.
    pub size: usize,
}

impl TaskResult {
    /// Creates a successful task result.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::types::TaskResult;
    ///
    /// let res = TaskResult::ok(0, vec![1, 2, 3], 3);
    /// assert!(res.error.is_none());
    /// ```
    #[inline]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        // Construct a TaskResult representing success.
        // - data: The processed byte vector.
        // - error: None, indicating no failure.
        // - index: To allow reordering at the writer stage.
        // - size: The actual length of valid data.
        Self { data, error: None, index, size }
    }

    /// Creates a failed task result from an error.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::types::TaskResult;
    /// use anyhow::anyhow;
    ///
    /// let err = anyhow!("something went wrong");
    /// let res = TaskResult::err(0, &err);
    /// assert!(res.error.is_some());
    /// ```
    #[inline]
    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        // Construct a TaskResult representing failure.
        // - data: Empty vector, as we have no valid output.
        // - error: The error string boxed for storage.
        // - index: Preserved so we know which chunk failed.
        // - size: 0, as there is no valid data.
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    #[test]
    fn test_processor_mode_label() {
        // Verify that the label method returns the expected string for Encrypt mode.
        assert_eq!(ProcessorMode::Encrypt.label(), "Encrypt");

        // Verify that the label method returns the expected string for Decrypt mode.
        assert_eq!(ProcessorMode::Decrypt.label(), "Decrypt");
    }

    #[test]
    fn test_processing_label() {
        // Verify that the label method returns "Encrypting..." for Encryption state.
        assert_eq!(Processing::Encryption.label(), "Encrypting...");

        // Verify that the label method returns "Decrypting..." for Decryption state.
        assert_eq!(Processing::Decryption.label(), "Decrypting...");
    }

    #[test]
    fn test_processing_mode_conversion() {
        // Ensure that converting Encryption state returns Encrypt mode.
        assert_eq!(Processing::Encryption.mode(), ProcessorMode::Encrypt);

        // Ensure that converting Decryption state returns Decrypt mode.
        assert_eq!(Processing::Decryption.mode(), ProcessorMode::Decrypt);
    }

    #[test]
    fn test_task_result_ok() {
        // Create test data for the result.
        let data = vec![1, 2, 3];

        // Create a success result using the helper method.
        let result = TaskResult::ok(1, data.clone(), 3);

        // Verify all fields are set correctly for a success case.
        assert_eq!(result.index, 1);
        assert_eq!(result.data, data);
        assert_eq!(result.size, 3);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_task_result_err() {
        // Create a test error.
        let err = anyhow!("test error");

        // Create a failure result using the helper method.
        let result = TaskResult::err(2, &err);

        // Verify all fields are set correctly for a failure case.
        assert_eq!(result.index, 2);
        assert!(result.data.is_empty());
        assert_eq!(result.size, 0);
        assert!(result.error.is_some());

        // Verify the error message matches.
        assert_eq!(result.error.as_deref(), Some("test error"));
    }
}
