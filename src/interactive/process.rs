//! Core processing workflow for interactive mode.
//!
//! This module orchestrates the actual encryption/decryption of a single file,
//! including validation, password prompting, progress reporting, and cleanup.

use super::prompt;
use crate::types::ProcessorMode;
use crate::{file, processor, tui};
use anyhow::{anyhow, Result};
use std::path::Path;
use std::sync::Arc;

/// Processes a single file (encrypts or decrypts) based on the mode.
///
/// This function handles the entire lifecycle of the operation:
/// 1. Validates input paths
/// 2. Checks for output overwrites
/// 3. Prompts for password
/// 4. Sets up progress reporting
/// 5. Executes the cryptographic operation
/// 6. Handles cleanup (optional deletion of source)
pub fn process_file(input_path: &Path, mode: ProcessorMode) -> Result<()> {
    // Determine output path (e.g., file.txt -> file.txt.enc)
    let output_path = file::get_output_path(input_path, mode);

    // 1. Validate input file exists and is readable
    file::validate_path(input_path, true)?;

    // 2. Check if output file already exists and ask for overwrite permission
    if file::validate_path(&output_path, false).is_err() && !prompt::ask_overwrite(&output_path)? {
        return Err(anyhow!("operation canceled by user"));
    }

    // 3. Get password from user
    //    - Encrypt mode: requires confirmation (enter twice)
    //    - Decrypt mode: enter once
    let password = prompt::ask_password(mode == ProcessorMode::Encrypt)?;

    // 4. Show summary info before starting
    tui::show_processing_info(mode, input_path.to_str().unwrap_or("?"));

    // 5. Prepare progress bar
    //    - Encrypt: size = physical file size
    //    - Decrypt: size = original unencrypted size (from header)
    let size = file::get_file_size(input_path, mode)?;
    let pb = tui::Progress::new(size);

    // Create thread-safe callback for progress updates
    let callback: Option<Arc<dyn Fn(u64) + Send + Sync>> = {
        let pb = pb.clone();
        Some(Arc::new(move |bytes| pb.inc(bytes)))
    };

    // 6. Execute the operation
    match mode {
        ProcessorMode::Encrypt => {
            processor::encrypt_file(input_path, &output_path, &password, callback)?
        }
        ProcessorMode::Decrypt => {
            processor::decrypt_file(input_path, &output_path, &password, callback)?
        }
    }

    // 7. Finish progress bar and show success
    pb.finish_with_message("Done");
    tui::show_success_info(mode, output_path.to_str().unwrap_or("?"));

    // 8. Optional: Delete original file
    if prompt::ask_delete_original(input_path, mode)? {
        file::remove_file(input_path)?;
        tui::show_source_deleted(input_path.to_str().unwrap_or("?"));
    }

    Ok(())
}
