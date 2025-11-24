//! File header management for encrypted files.
//!
//! This module provides structures and functions for managing file headers
//! in encrypted files, including:
//! - **`metadata`**: Core Header struct and data accessors
//! - **`encoding`**: Section encoding using Reed-Solomon error correction
//! - **`marshal`**: Marshaling/unmarshaling headers to/from bytes
//! - **`verification`**: MAC computation and header verification
//!
//! # Examples
//!
//! ```no_run
//! use sweetbyte::header::{Header, marshal, verification};
//!
//! // Create and configure a header
//! let mut header = Header::new().unwrap();
//! header.set_original_size(1024);
//! header.set_protected(true);
//!
//! // Marshal to bytes
//! let salt = vec![0u8; 32];
//! let key = vec![0u8; 64];
//! let bytes = marshal::marshal(&header, &salt, &key).unwrap();
//!
//! // Unmarshal from bytes
//! let mut header2 = Header::new().unwrap();
//! let mut reader = std::io::Cursor::new(bytes);
//! marshal::unmarshal(&mut header2, &mut reader).unwrap();
//!
//! // Verify header
//! verification::verify_header(&header2, &key).unwrap();
//! ```

pub mod encoding;
pub mod marshal;
pub mod metadata;
pub mod verification;

// Re-export main types for convenience
pub use metadata::{
    Header, CURRENT_VERSION, FLAG_PROTECTED, HEADER_DATA_SIZE, MAC_SIZE, MAGIC_BYTES, MAGIC_SIZE,
};
