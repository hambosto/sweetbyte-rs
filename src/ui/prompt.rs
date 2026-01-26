//! Interactive user prompts.
//!
//! This module handles user input via the terminal using the `dialoguer` crate.
//! It supports:
//! - Password input (with confirmation and validation).
//! - Selection menus (file lists, operation modes).
//! - Confirmation dialogs (Yes/No).

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::file::File;
use crate::types::ProcessorMode;

/// A handler for interactive CLI prompts.
pub struct Prompt {
    /// Minimum required length for new passwords.
    password_min_length: usize,

    /// Visual theme for prompts.
    theme: ColorfulTheme,
}

impl Prompt {
    /// Creates a new prompt handler.
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length, theme: ColorfulTheme::default() }
    }

    /// Prompts the user to enter and confirm an encryption password.
    ///
    /// # Returns
    ///
    /// The validated password string.
    ///
    /// # Errors
    ///
    /// Returns an error if the passwords don't match or input is cancelled.
    pub fn prompt_encryption_password(&self) -> Result<String> {
        // First entry.
        let password = self.prompt_password("Enter encryption password")?;

        // Confirmation entry.
        let confirmation = self.prompt_password("Confirm password")?;

        // Verify match.
        ensure!(password == confirmation, "password do not match");

        Ok(password)
    }

    /// Prompts the user for a decryption password (no confirmation needed).
    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password")
    }

    /// Displays a menu to select the operation mode (Encrypt/Decrypt).
    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        let modes = ProcessorMode::ALL;

        // Create display labels.
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        // Show selection menu.
        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("mode selection failed: {e}"))?;

        Ok(modes[idx])
    }

    /// Displays a menu to select a file from a list.
    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        ensure!(!files.is_empty(), "no files available for selection");

        // Format file options: "filename" or "path/to/filename".
        let display_names: Vec<String> = files
            .iter()
            .map(|f| f.path().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.path().display().to_string()))
            .collect();

        // Show selection menu.
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("file selection failed: {e}"))?;

        Ok(files[selection].path().to_path_buf())
    }

    /// Asks the user for confirmation to overwrite an existing file.
    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        self.confirm(&format!("Output file {filename} already exists. Overwrite?"))
    }

    /// Asks the user for confirmation to delete the source file.
    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        self.confirm(&format!("Delete {file_type} file {filename}?"))
    }

    /// Helper to prompt for a password with validation.
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<()> {
                // Reject empty or whitespace-only passwords.
                ensure!(!input.trim().is_empty(), "password cannot be empty or whitespace only");

                // Enforce minimum length.
                ensure!(input.len() >= self.password_min_length, "password must be at least {} characters long", self.password_min_length);
                Ok(())
            })
            .interact()
            .map_err(|e| anyhow!("password input failed: {e}"))
    }

    /// Helper to show a Yes/No confirmation dialog.
    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|e| anyhow!("confirmation failed: {e}"))
    }
}
