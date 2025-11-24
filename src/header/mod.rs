//! File header management for encrypted files.
//!
//! This module provides structures and functions for managing file headers
//! in encrypted files, including:
//! - **`metadata`**: Core Header struct and data accessors
//! - **`encoding`**: Section encoding using Reed-Solomon error correction
//! - **`marshal`**: Marshaling/unmarshaling headers to/from bytes
//! - **`verification`**: MAC computation and header verification
pub mod encoding;
pub mod marshal;
pub mod metadata;
pub mod verification;

// Re-export main types for convenience
pub use metadata::{
    CURRENT_VERSION, FLAG_PROTECTED, HEADER_DATA_SIZE, Header, MAC_SIZE, MAGIC_BYTES, MAGIC_SIZE,
};
