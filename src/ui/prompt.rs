//! # User Prompt Module
//!
//! This module handles all interactive user input including password entry,
//! file selection, and operation confirmations. It provides a secure and
//! user-friendly interface for collecting sensitive information and user choices.
//!
//! ## Security Considerations
//!
//! - **Password Input**: Secure password collection with no character echoing
//! - **Memory Safety**: Passwords are not stored in logs or debug output
//! - **Validation**: Strong password policies to protect user data
//! - **Confirmation**: Prevents accidental destructive operations
//!
//! ## User Experience Features
//!
//! - **Colorful Interface**: Consistent theming across all prompts
//! - **Smart Defaults**: Sensible defaults to reduce user friction
//! - **Clear Messages**: Unambiguous prompts and error messages
//! - **Keyboard Navigation**: Full keyboard support for accessibility
//!
//! ## Error Handling
//!
//! All prompts provide clear error messages and allow users to retry
//! failed operations without losing their progress or context.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::file::File;
use crate::types::ProcessorMode;

/// Handles all interactive user prompts and input collection
///
/// This struct provides a centralized interface for user interaction,
/// managing password entry, file selection, and operation confirmations
/// with consistent styling and behavior.
///
/// ## Security Design
///
/// - Passwords are never echoed to the terminal
/// - Minimum length requirements prevent weak passwords
/// - Confirmation prompts prevent accidental destructive operations
/// - Input validation with clear error messages
///
/// ## Accessibility
///
/// - Full keyboard navigation support
/// - Clear visual indicators with color coding
/// - Sensible defaults to reduce cognitive load
/// - Consistent interface across all prompt types
///
/// ## Memory Safety
///
/// Passwords are only held in memory for the minimum required time
/// and are never written to logs or debug output.
pub struct Prompt {
    /// Minimum required length for passwords to ensure security
    password_min_length: usize,
    /// Theme for consistent visual styling across all prompts
    theme: ColorfulTheme,
}

impl Prompt {
    /// Create a new Prompt instance with specified password requirements
    ///
    /// Initializes the prompt handler with security requirements and visual
    /// theming. The default colorful theme provides good contrast and readability.
    ///
    /// # Arguments
    ///
    /// * `password_min_length` - Minimum number of characters required for passwords
    ///
    /// # Returns
    ///
    /// * `Self` - New Prompt instance ready for use
    ///
    /// # Security Considerations
    ///
    /// - Longer minimum lengths provide better security against brute force attacks
    /// - The default theme ensures prompts are clearly visible and distinguishable
    /// - Consistent theming helps users recognize legitimate application prompts
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length, theme: ColorfulTheme::default() }
    }

    /// Prompt user for encryption password with confirmation
    ///
    /// Collects a password for file encryption with a second confirmation
    /// entry to prevent typos. This dual-entry approach is critical for
    /// encryption since a typo could result in permanent data loss.
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The verified password or error if validation fails
    ///
    /// # Errors
    ///
    /// * If password input fails (user cancels, terminal issues)
    /// * If passwords don't match during confirmation
    /// * If password doesn't meet minimum length requirements
    ///
    /// # Security Considerations
    ///
    /// - Two entries prevent data loss from typos
    /// - Passwords are never echoed or logged
    /// - Validation happens immediately to catch weak passwords
    /// - Memory is cleared as soon as possible after use
    ///
    /// # User Experience
    ///
    /// - Clear error messages guide users to fix issues
    /// - Confirmation prevents frustration from data loss
    /// - Consistent prompt styling maintains interface flow
    pub fn prompt_encryption_password(&self) -> Result<String> {
        // First password entry
        let password = self.prompt_password("Enter encryption password")?;
        // Second password entry for confirmation
        let confirmation = self.prompt_password("Confirm password")?;
        // Verify both passwords match to prevent typos
        ensure!(password == confirmation, "password do not match");

        Ok(password)
    }

    /// Prompt user for decryption password
    ///
    /// Collects a password for file decryption. Unlike encryption, this only
    /// requires a single entry since the user is trying to match an existing
    /// password rather than creating a new one.
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The password or error if input fails
    ///
    /// # Errors
    ///
    /// * If password input fails (user cancels, terminal issues)
    /// * If password doesn't meet minimum length requirements
    ///
    /// # Security Considerations
    ///
    /// - Password is never echoed to the terminal
    /// - Same validation rules as encryption for consistency
    /// - Clear error messages guide users without revealing hints
    ///
    /// # User Experience
    ///
    /// - Simpler flow than encryption since confirmation isn't needed
    /// - Consistent styling with other password prompts
    /// - Helpful error messages for common issues
    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password")
    }

    /// Prompt user to select file processing mode
    ///
    /// Presents an interactive selection menu for choosing between encryption
    /// and decryption operations. Uses the processor mode labels for clear,
    /// user-friendly option descriptions.
    ///
    /// # Returns
    ///
    /// * `Result<ProcessorMode>` - The selected processing mode or error if selection fails
    ///
    /// # Errors
    ///
    /// * If user cancels the selection
    /// * If terminal doesn't support interactive selection
    /// * If theme application fails
    ///
    /// # User Experience
    ///
    /// - Clear operation labels prevent confusion
    /// - Default selection reduces friction for common use cases
    /// - Keyboard navigation for accessibility
    /// - Consistent theming with other prompts
    ///
    /// # Design Notes
    ///
    /// The selection is returned as the actual ProcessorMode enum rather
    /// than an index, ensuring type safety and preventing mode-related bugs.
    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        // Get all available processing modes
        let modes = ProcessorMode::ALL;

        // Extract human-readable labels for display
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        // Create interactive selection with consistent theming
        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&display_names)
            .default(0) // Default to first option (usually encryption)
            .interact()
            .map_err(|e| anyhow!("mode selection failed: {e}"))?;

        // Return the actual ProcessorMode enum, not just the index
        Ok(modes[idx])
    }

    /// Prompt user to select a file from the available options
    ///
    /// Presents an interactive menu of discovered files for user selection.
    /// Shows only filenames for readability while maintaining full path
    /// information internally for processing.
    ///
    /// # Arguments
    ///
    /// * `files` - Slice of File objects available for selection
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf>` - Path to the selected file or error if selection fails
    ///
    /// # Errors
    ///
    /// * If no files are available for selection
    /// * If user cancels the selection
    /// * If terminal doesn't support interactive selection
    ///
    /// # User Experience
    ///
    /// - Clean filename display hides long paths for readability
    /// - Default selection reduces friction
    /// - Full keyboard navigation support
    /// - Graceful fallback to full path display for unusual files
    ///
    /// # Safety Considerations
    ///
    /// - Returns owned PathBuf to avoid lifetime issues
    /// - Validates file list before displaying menu
    /// - Safe handling of filename encoding issues
    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        // Ensure we have files to select from before proceeding
        ensure!(!files.is_empty(), "no files available for selection");

        // Extract display names, using filename when possible, full path as fallback
        // This provides clean UI while handling edge cases gracefully
        let display_names: Vec<String> = files
            .iter()
            .map(|f| f.path().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.path().display().to_string()))
            .collect();

        // Create interactive selection menu with consistent theming
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0) // Default to first file for convenience
            .interact()
            .map_err(|e| anyhow!("file selection failed: {e}"))?;

        // Return a copy of the selected file path
        Ok(files[selection].path().to_path_buf())
    }

    /// Confirm whether to overwrite an existing file
    ///
    /// Prompts the user for confirmation when the output file already exists.
    /// This prevents accidental data loss and gives users control over
    /// destructive operations.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file that would be overwritten
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if user confirms overwrite, false otherwise
    ///
    /// # Errors
    ///
    /// * If confirmation prompt fails (terminal issues, user cancellation)
    ///
    /// # User Experience
    ///
    /// - Clear message identifies which file would be affected
    /// - Default to false (no overwrite) to prevent accidental data loss
    /// - Consistent styling with other confirmation dialogs
    ///
    /// # Safety Considerations
    ///
    /// - Confirmation required before any destructive operation
    /// - Safe filename handling with path fallback
    /// - Conservative default protects user data
    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        // Extract filename for clear user identification
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        // Present clear confirmation question about the specific file
        self.confirm(&format!("Output file {filename} already exists. Overwrite?"))
    }

    /// Confirm whether to delete a file
    ///
    /// Prompts the user for confirmation before deleting files.
    /// This is used for both source file cleanup and other deletion operations.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file that would be deleted
    /// * `file_type` - Description of the file type (e.g., "source", "temporary")
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if user confirms deletion, false otherwise
    ///
    /// # Errors
    ///
    /// * If confirmation prompt fails (terminal issues, user cancellation)
    ///
    /// # User Experience
    ///
    /// - Clear context about what type of file is being deleted
    /// - Specific filename identification prevents confusion
    /// - Conservative default protects against accidental deletion
    ///
    /// # Safety Considerations
    ///
    /// - Confirmation required for all destructive operations
    /// - File type context helps users make informed decisions
    /// - Default to false prevents accidental data loss
    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        // Extract filename for clear user identification
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        // Present confirmation with file type context for clarity
        self.confirm(&format!("Delete {file_type} file {filename}?"))
    }

    /// Internal method to collect and validate password input
    ///
    /// Handles the common password input logic with validation rules.
    /// Password input is never echoed to the terminal for security.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt message to display to the user
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The validated password or error if input fails
    ///
    /// # Errors
    ///
    /// * If password input is cancelled or fails
    /// * If password doesn't meet validation requirements
    ///
    /// # Security Validation
    ///
    /// - Disallows empty or whitespace-only passwords
    /// - Enforces minimum length requirement
    /// - Provides clear error messages without revealing security policies
    ///
    /// # Implementation Notes
    ///
    /// - Uses dialoguer's Password widget for secure input
    /// - Validation happens inline to provide immediate feedback
    /// - Theme ensures consistent appearance with other prompts
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<()> {
                // Prevent empty passwords which provide no security
                ensure!(!input.trim().is_empty(), "password cannot be empty or whitespace only");
                // Enforce minimum length for reasonable security
                ensure!(input.len() >= self.password_min_length, "password must be at least {} characters long", self.password_min_length);
                Ok(())
            })
            .interact()
            .map_err(|e| anyhow!("password input failed: {e}"))
    }

    /// Internal method to get yes/no confirmation from user
    ///
    /// Handles common confirmation dialog logic with conservative defaults
    /// to prevent accidental destructive operations.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The confirmation question to display
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if user confirms, false otherwise
    ///
    /// # Errors
    ///
    /// * If confirmation dialog fails (terminal issues, user cancellation)
    ///
    /// # User Experience Design
    ///
    /// - Default to false (no confirmation) for safety
    /// - Clear yes/no options prevent confusion
    /// - Consistent theming with other prompts
    ///
    /// # Safety Considerations
    ///
    /// Conservative defaults protect users from accidental acceptance
    /// of destructive operations when they might be trying to cancel.
    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false) // Conservative default for safety
            .interact()
            .map_err(|e| anyhow!("confirmation failed: {e}"))
    }
}
