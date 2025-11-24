//! File selection logic for interactive mode.
//!
//! This module handles the discovery and selection of files eligible for processing.

use crate::types::ProcessorMode;
use crate::{file, tui};
use anyhow::Result;
use std::path::PathBuf;

/// Finds eligible files and prompts the user to select one.
///
/// # Arguments
///
/// * `mode` - The processing mode (Encrypt/Decrypt) used to filter files.
///
/// # Returns
///
/// Returns `Some(PathBuf)` if a file was selected, or `None` if no eligible files were found.
pub fn choose_file(mode: ProcessorMode) -> Result<Option<PathBuf>> {
    // 1. Find all files that match the criteria for the given mode
    //    (e.g., non-encrypted files for Encrypt mode, .enc files for Decrypt mode)
    let eligible_files = file::find_eligible_files(mode)?;

    // 2. Handle case where no files are found
    if eligible_files.is_empty() {
        println!("No eligible files found for {:?} operation", mode);
        return Ok(None);
    }

    // 3. Present list to user via TUI
    let selected = tui::choose_file(&eligible_files)?;
    Ok(Some(selected))
}
