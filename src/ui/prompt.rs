use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::file::File;
use crate::types::ProcessorMode;

/// Interactive terminal prompts for user input.
///
/// Provides methods for password input with confirmation,
/// mode selection, file selection, and confirmations.
pub struct Prompt {
    /// Minimum password length requirement.
    password_min_length: usize,
    /// Colorful theme for dialoguer prompts.
    theme: ColorfulTheme,
}

impl Prompt {
    /// Creates a new Prompt instance.
    ///
    /// # Arguments
    /// * `password_min_length` - Minimum allowed password length.
    ///
    /// # Returns
    /// A new Prompt instance.
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length, theme: ColorfulTheme::default() }
    }

    /// Prompts for an encryption password with confirmation.
    ///
    /// Asks for a password, asks for confirmation, and ensures
    /// both entries match.
    ///
    /// # Returns
    /// The confirmed password, or an error if input failed.
    pub fn prompt_encryption_password(&self) -> Result<String> {
        // Get password.
        let password = self.prompt_password("Enter encryption password")?;
        // Get password confirmation.
        let confirmation = self.prompt_password("Confirm password")?;

        // Ensure passwords match.
        ensure!(password == confirmation, "password do not math");

        Ok(password)
    }

    /// Prompts for a decryption password (no confirmation).
    ///
    /// # Returns
    /// The password, or an error if input failed.
    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password")
    }

    /// Prompts user to select encryption or decryption mode.
    ///
    /// Displays a selection menu with both options.
    ///
    /// # Returns
    /// The selected ProcessorMode.
    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        let modes = ProcessorMode::ALL;
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        // Show selection dialog.
        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("mode selection failed: {e}"))?;

        Ok(modes[idx])
    }

    /// Prompts user to select a file from a list.
    ///
    /// # Arguments
    /// * `files` - List of files to choose from (must not be empty).
    ///
    /// # Returns
    /// The path to the selected file.
    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        ensure!(!files.is_empty(), "no files available for selection");

        // Convert files to display strings.
        let display_names: Vec<String> = files.iter().map(|f| f.path().display().to_string()).collect();
        // Show file selection dialog.
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("file selection failed: {e}"))?;

        Ok(files[selection].path().to_path_buf())
    }

    /// Prompts user to confirm overwriting an existing file.
    ///
    /// # Arguments
    /// * `path` - Path to the existing file.
    ///
    /// # Returns
    /// True if user confirmed, false otherwise.
    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        self.confirm(&format!("Output file {} already exists. Overwrite?", path.display()))
    }

    /// Prompts user to confirm deleting a source file.
    ///
    /// # Arguments
    /// * `path` - Path to the file to delete.
    /// * `file_type` - Description of file type (e.g., "original" or "encrypted").
    ///
    /// # Returns
    /// True if user confirmed, false otherwise.
    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        self.confirm(&format!("Delete {} file {}?", file_type, path.display()))
    }

    /// Internal password prompt with validation.
    ///
    /// # Arguments
    /// * `prompt` - The prompt text to display.
    ///
    /// # Returns
    /// The password string, or an error.
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            // Validate password meets minimum requirements.
            .validate_with(|input: &String| -> Result<()> {
                ensure!(!input.trim().is_empty(), "password cannot be empty or whitespace only");
                ensure!(input.len() >= self.password_min_length, "password must be at least {} characters long", self.password_min_length);

                Ok(())
            })
            .interact()
            .map_err(|e| anyhow!("password input failed: {e}"))
    }

    /// Internal confirmation prompt.
    ///
    /// # Arguments
    /// * `prompt` - The prompt text to display.
    ///
    /// # Returns
    /// True if user confirmed (yes), false otherwise.
    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|e| anyhow!("confirmation failed: {e}"))
    }
}
