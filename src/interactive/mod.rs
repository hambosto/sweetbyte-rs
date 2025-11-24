//! Interactive mode orchestration.
//!
//! This module serves as the entry point for the interactive CLI mode.
//! It coordinates the user interaction flow by:
//! 1. Prompting for processing mode (Encrypt/Decrypt)
//! 2. Selecting files to process
//! 3. Initiating the processing workflow
//!
//! The logic is split into focused submodules:
//! - `prompt`: Handles user input (passwords, confirmations)
//! - `select`: Handles file discovery and selection
//! - `process`: Handles the core encryption/decryption workflow

mod process;
mod prompt;
mod select;

use crate::tui;
use anyhow::Result;

/// Runs the interactive mode application loop.
///
/// This function:
/// 1. Displays the application banner
/// 2. Asks the user for the desired mode (Encrypt/Decrypt)
/// 3. Prompts for file selection based on the mode
/// 4. Initiates processing if a file is selected
///
/// # Returns
///
/// Returns `Ok(())` on successful execution or if the user cancels.
/// Returns an error if any I/O or processing step fails.
pub fn run() -> Result<()> {
    // 1. Show welcome banner
    tui::print_banner();

    // 2. Ask user for mode (Encrypt vs Decrypt)
    let mode = prompt::ask_mode()?;

    // 3. Select file and process it
    // If choose_file returns None, it means no eligible files were found
    if let Some(file) = select::choose_file(mode)? {
        process::process_file(&file, mode)?;
    }

    Ok(())
}
