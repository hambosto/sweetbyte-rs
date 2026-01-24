//! Core Type Definitions and Error Handling
//!
//! This module contains the fundamental types used throughout the SweetByte
//! application. It defines enums for processing modes, structures for parallel
//! task management, and provides conversion between related types.
//!
//! ## Design Principles
//!
//! - **Type Safety**: Rust's type system prevents invalid states
//! - **Zero-Cost Abstractions**: Compile-time guarantees without runtime overhead
//! - **Clarity**: Type names clearly express their purpose
//! - **Interoperability**: Types work well together across the codebase
//!
//! ## Error Handling Strategy
//!
//! The module uses Result types for error handling while maintaining
//! type safety for success cases. Error information is preserved and
//! propagated through the call stack for debugging and user feedback.

use std::fmt::{Display, Formatter, Result};

/// Processing mode for file operations
///
/// This enum represents the high-level operation mode the user wants
/// to perform. It's used primarily for UI interactions and file filtering
/// logic. The distinction from `Processing` is that this represents the
/// user's intent rather than the in-progress operation.
///
/// ## Usage Context
///
/// - **File Discovery**: Determines which files are eligible
/// - **UI Selection**: Presented to users for mode choice
/// - **Path Generation**: Determines output filename transformations
/// - **Validation Logic**: Applies different rules based on mode
///
/// ## Security Implications
///
/// The mode determines which files are shown to users, preventing
/// accidental encryption of already-encrypted files or decryption
/// of unencrypted files that could waste time or cause confusion.
#[derive(Clone, Copy, PartialEq)]
pub enum ProcessorMode {
    /// Encrypt unencrypted files
    ///
    /// This mode is used when users want to encrypt plaintext files.
    /// File discovery will show only files that don't have the .swx
    /// extension and aren't excluded by other rules.
    Encrypt,

    /// Decrypt encrypted files
    ///
    /// This mode is used when users want to decrypt SweetByte files.
    /// File discovery will show only files with the .swx extension
    /// that can be parsed as valid encrypted files.
    Decrypt,
}

impl ProcessorMode {
    /// All available processor modes for iteration
    ///
    /// This constant provides an array of all modes for use in UI
    /// components that need to enumerate all available options.
    /// It ensures that all modes are consistently presented to users.
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    /// Get a human-readable label for the mode
    ///
    /// This method provides a user-friendly label for displaying
    /// the mode in UI components. The labels are concise and
    /// follow standard terminology for encryption software.
    ///
    /// # Returns
    ///
    /// A string slice suitable for display to users
    ///
    /// # Localization
    ///
    /// Currently returns English labels. Future versions could
    /// integrate with a localization system for international support.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    /// Format the ProcessorMode for display
    ///
    /// This implementation provides a clean string representation
    /// suitable for user interfaces, logging, and debugging.
    /// It delegates to the label() method for consistency.
    ///
    /// # Arguments
    ///
    /// * `f` - Formatter to write the representation to
    ///
    /// # Returns
    ///
    /// Result indicating successful formatting
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Active processing operation state
///
/// This enum represents the current state of a processing operation.
/// Unlike `ProcessorMode` which represents user intent, this enum
/// represents an operation that is actively in progress.
///
/// ## Usage Context
///
/// - **Worker Threads**: Indicates the operation being performed
/// - **Progress Display**: Shows current operation to users
/// - **Configuration**: Determines algorithm choices and parameters
/// - **Error Context**: Provides context for error messages
///
/// ## Distinction from ProcessorMode
///
/// `ProcessorMode` = What the user wants to do
/// `Processing` = What the system is currently doing
///
/// This separation allows for clearer code intent and prevents
/// confusion between user intent and system state.
#[derive(Clone, Copy)]
pub enum Processing {
    /// Currently encrypting data
    ///
    /// This state indicates that the system is actively encrypting
    /// file content. It configures algorithms for encryption mode
    /// and displays appropriate progress messages to users.
    Encryption,

    /// Currently decrypting data
    ///
    /// This state indicates that the system is actively decrypting
    /// file content. It configures algorithms for decryption mode
    /// and displays appropriate progress messages to users.
    Decryption,
}

impl Processing {
    /// Get a human-readable label for the current operation
    ///
    /// This method provides a status message suitable for display
    /// during active processing. The labels include ellipsis to
    /// indicate ongoing operations.
    ///
    /// # Returns
    ///
    /// A string slice representing the current operation status
    ///
    /// # UI Context
    ///
    /// These labels are designed for progress displays and status
    /// bars, providing clear feedback about what operation is in progress.
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    /// Convert processing state to corresponding processor mode
    ///
    /// This method bridges the gap between the active processing
    /// state and the user intent mode, allowing conversions between
    /// the two related but distinct enum types.
    ///
    /// # Returns
    ///
    /// The corresponding ProcessorMode for this Processing state
    ///
    /// # Usage
    ///
    /// Useful for determining output file paths, applying the
    /// correct validation logic, and other mode-dependent operations.
    #[inline]
    pub fn mode(self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    /// Format the Processing state for display
    ///
    /// This implementation provides a user-friendly string
    /// representation suitable for progress displays and status
    /// messages during active operations.
    ///
    /// # Arguments
    ///
    /// * `f` - Formatter to write the representation to
    ///
    /// # Returns
    ///
    /// Result indicating successful formatting
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

/// Task for parallel processing workers
///
/// This struct represents a unit of work that can be processed by
/// worker threads in the parallel processing system. Each task
/// contains a chunk of data and its position within the overall
/// file for proper reconstruction.
///
/// ## Thread Safety
///
/// Task instances are thread-safe for sending between threads
/// as they contain owned data rather than references.
///
/// ## Memory Management
///
/// The data field contains owned `Vec<u8>` data, meaning each
/// task has its own copy of the chunk to process. This design
/// prioritizes thread safety over memory efficiency but provides
/// cleaner code and better isolation between worker threads.
///
/// ## Index Semantics
///
/// The index represents the position of this chunk within the
/// overall file processing sequence, enabling proper reconstruction
/// of the final output in the correct order.
pub struct Task {
    /// The data chunk to be processed
    ///
    /// This contains a portion of the file data that will be
    /// encrypted or decrypted by a worker thread. The size of each
    /// chunk is determined by the CHUNK_SIZE configuration constant.
    pub data: Vec<u8>,

    /// Position index of this chunk in the overall sequence
    ///
    /// This zero-based index represents where this chunk belongs
    /// in the final reconstructed output. It's essential for maintaining
    /// data order during parallel processing.
    pub index: u64,
}

/// Result of processing a task by a worker thread
///
/// This struct represents the outcome of processing a task, containing
/// either successfully processed data or an error that occurred during
/// processing. It enables the main thread to collect and combine results
/// from parallel worker operations.
///
/// ## Error Handling
///
/// The error field allows graceful handling of processing failures
/// without crashing the entire operation. Individual chunk failures
/// can be logged while attempting to process remaining chunks.
///
/// ## Thread Safety
///
/// TaskResult instances are thread-safe for sending between threads
/// as they contain only owned data and no references.
///
/// ## Memory Efficiency
///
/// Uses `Box<str>` for error messages to reduce memory overhead
/// compared to String while still providing owned data.
pub struct TaskResult {
    /// The processed data (empty if error occurred)
    ///
    /// Contains the encrypted or decrypted result of processing
    /// the task data. If processing failed, this will be empty
    /// to avoid returning partially processed data.
    pub data: Vec<u8>,

    /// Error message if processing failed (None if successful)
    ///
    /// Contains a description of what went wrong during processing.
    /// Using `Box<str>` provides memory efficiency while maintaining
    /// ownership of the error message.
    pub error: Option<Box<str>>,

    /// Original index of the task (preserved for ordering)
    ///
    /// This matches the index from the original Task and is used
    /// to ensure results are combined in the correct order even
    /// when parallel processing completes out of order.
    pub index: u64,

    /// Size of the original data (0 if error occurred)
    ///
    /// Represents the size of the input data that was processed.
    /// This can be useful for progress tracking and debugging.
    pub size: usize,
}

impl TaskResult {
    /// Create a successful TaskResult
    ///
    /// This constructor creates a TaskResult representing successful
    /// processing of a task. It contains the processed data and
    /// metadata about the operation.
    ///
    /// # Arguments
    ///
    /// * `index` - Original task index for ordering
    /// * `data` - Successfully processed data
    /// * `size` - Size of the processed data
    ///
    /// # Returns
    ///
    /// A TaskResult with error=None indicating success
    ///
    /// # Usage
    ///
    /// Used by worker threads when processing completes successfully.
    /// The result can be easily combined with other successful results.
    #[inline]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    /// Create a failed TaskResult
    ///
    /// This constructor creates a TaskResult representing a processing
    /// failure. It captures the error information while ensuring no
    /// partially processed data is returned.
    ///
    /// # Arguments
    ///
    /// * `index` - Original task index for ordering
    /// * `error` - The error that occurred during processing
    ///
    /// # Returns
    ///
    /// A TaskResult with error=Some(description) and empty data
    ///
    /// # Error Handling
    ///
    /// The error is converted to a boxed string to reduce memory
    /// overhead while preserving the error message for logging and
    /// user feedback. The data field is empty to prevent returning
    /// partially processed or corrupted data.
    ///
    /// # Usage
    ///
    /// Used by worker threads when processing fails for any reason,
    /// including cryptographic errors, I/O failures, or validation
    /// problems. This allows the main thread to handle errors gracefully.
    #[inline]
    pub fn err(index: u64, error: &anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}
