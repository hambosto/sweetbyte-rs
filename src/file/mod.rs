//! File management utilities for SweetByte encryption operations.
//!
//! This module provides three focused sub-modules:
//! - **`operations`**: Core file I/O operations (open_file, remove_file)
//! - **`validation`**: Path validation and filtering (validate_path, get_output_path, etc.)
//! - **`discovery`**: File discovery for batch processing (find_eligible_files)
//!
//! # Examples
//!
//! ```no_run
//! use sweetbyte::file;
//! use sweetbyte::types::ProcessorMode;
//! use std::path::Path;
//!
//! // Open a file
//! let (file, metadata) = file::open_file(Path::new("example.txt"))?;
//!
//! // Determine output path for encryption
//! let output = file::get_output_path(Path::new("doc.pdf"), ProcessorMode::Encrypt);
//!
//! // Find all eligible files for encryption
//! let files = file::find_eligible_files(ProcessorMode::Encrypt)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod discovery;
pub mod operations;
pub mod validation;

// Re-export commonly used functions for convenience
pub use discovery::find_eligible_files;
pub use operations::{get_file_size, open_file, remove_file};
pub use validation::{get_output_path, validate_path};
