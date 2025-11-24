//! File management utilities for SweetByte encryption operations.
//!
//! This module provides three focused sub-modules:
//! - **`operations`**: Core file I/O operations (open_file, remove_file)
//! - **`validation`**: Path validation and filtering (validate_path, get_output_path, etc.)
//! - **`discovery`**: File discovery for batch processing (find_eligible_files)
pub mod discovery;
pub mod operations;
pub mod validation;

// Re-export commonly used functions for convenience
pub use discovery::find_eligible_files;
pub use operations::{get_file_size, open_file, remove_file};
pub use validation::{get_output_path, validate_path};
