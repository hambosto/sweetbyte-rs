//! User input handling for interactive mode.
//!
//! This module wraps TUI prompts with specific logic for the application's needs,
//! such as password confirmation and safe overwrite checks.

use crate::tui;
use crate::types::ProcessorMode;
use anyhow::Result;

/// Prompts the user to select a processing mode (Encrypt or Decrypt).
pub fn ask_mode() -> Result<ProcessorMode> {
    tui::ask_processing_mode()
}

/// Prompts the user for a password, optionally requiring confirmation.
///
/// # Arguments
///
/// * `confirm` - If true, asks the user to enter the password twice and verifies they match.
///   This is typically used for encryption to prevent typos.
///
/// # Errors
///
/// Returns an error if:
/// - The user cancels the prompt
/// - Passwords do not match (when `confirm` is true)
pub fn ask_password(confirm: bool) -> Result<String> {
    // 1. Ask for password
    let password = tui::ask_password("Enter password:")?;

    // 2. If confirmation is required (e.g. encryption), ask again
    if confirm {
        let confirmation = tui::ask_password("Confirm password:")?;
        if password != confirmation {
            anyhow::bail!("passwords do not match");
        }
    }
    Ok(password)
}

/// Asks the user if they want to overwrite an existing output file.
///
/// # Arguments
///
/// * `path` - The path of the file that would be overwritten
pub fn ask_overwrite(path: &std::path::Path) -> Result<bool> {
    tui::ask_confirm(&format!(
        "Output file '{}' exists. Overwrite?",
        path.display()
    ))
}

/// Asks the user if they want to delete the source file after successful processing.
///
/// # Arguments
///
/// * `path` - The path of the file to delete
/// * `mode` - The operation mode, used to customize the prompt message
pub fn ask_delete_original(path: &std::path::Path, mode: ProcessorMode) -> Result<bool> {
    // Customize message based on what we are deleting
    let file_type = match mode {
        ProcessorMode::Encrypt => "original",
        ProcessorMode::Decrypt => "encrypted",
    };
    tui::ask_confirm(&format!("Delete {} file '{}'?", file_type, path.display()))
}
