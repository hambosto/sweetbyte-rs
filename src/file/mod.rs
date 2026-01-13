//! File operations module for SweetByte.

pub mod discovery;
pub mod operations;
pub mod validation;

pub use discovery::find_eligible_files;
pub use operations::{
    create_file, get_file_info, get_file_info_list, get_output_path, is_encrypted_file, open_file,
    remove_file,
};
pub use validation::{is_excluded, validate_path};
