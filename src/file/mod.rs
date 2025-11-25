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
pub use discovery::{find_eligible_files, find_eligible_files_with_display};
pub use operations::{get_file_size, open_file, remove_file};
pub use validation::{
    get_clean_path, get_output_path, get_output_path_with_display, is_encrypted_file, validate_path,
};
