//! Interactive prompts for wizard mode.
//!
//! Provides password input with confirmation, mode selection,
//! file selection, and confirmation dialogs using dialoguer.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::file::File;
use crate::types::ProcessorMode;

/// Interactive prompt handler for wizard mode.
///
/// Provides styled prompts for passwords, selections, and confirmations
/// using the colorful theme.
pub struct Prompt {
    /// Minimum password length requirement.
    password_min_length: usize,

    /// Dialoguer theme for consistent styling.
    theme: ColorfulTheme,
}

impl Prompt {
    /// Creates a new prompt handler.
    ///
    /// # Arguments
    ///
    /// * `password_min_length` - Minimum valid password length.
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length, theme: ColorfulTheme::default() }
    }

    /// Prompts for an encryption password with confirmation.
    ///
    /// For security, encryption requires the user to enter their password twice
    /// to prevent typos. If the two entries don't match, an error is returned.
    /// This ensures the user knows what password they set.
    ///
    /// # Process
    ///
    /// 1. Prompt for password with "Enter encryption password"
    /// 2. Prompt again with "Confirm password"
    /// 3. Compare the two entries
    /// 4. Return error if they don't match, otherwise return the password
    ///
    /// # Returns
    ///
    /// The confirmed password string on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Password validation fails (empty, whitespace, too short)
    /// - Confirmation doesn't match original entry
    pub fn prompt_encryption_password(&self) -> Result<String> {
        // First password prompt with validation.
        // The internal prompt_password() handles validation (length, non-empty).
        let password = self.prompt_password("Enter encryption password")?;

        // Confirmation prompt - same validation applies.
        // Users often make typos; confirmation catches this before encryption.
        let confirmation = self.prompt_password("Confirm password")?;

        // Compare the two entries.
        // ensure! macro creates an error if the condition is false.
        // This prevents encrypting with an unintended password.
        ensure!(password == confirmation, "password do not match");

        // Return the confirmed password.
        // This will be used for key derivation.
        Ok(password)
    }

    /// Prompts for a decryption password.
    ///
    /// Decryption only requires a single password prompt since the user
    /// should already know their password. If the password is wrong,
    /// the HMAC verification during header parsing will fail.
    ///
    /// # Returns
    ///
    /// The password string from user input.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Password validation fails (empty, whitespace, too short)
    pub fn prompt_decryption_password(&self) -> Result<String> {
        // Single prompt for decryption - no confirmation needed.
        // Wrong password will be caught by HMAC verification later.
        self.prompt_password("Enter decryption password")
    }

    /// Prompts user to select encryption or decryption mode.
    ///
    /// Displays a selection menu with "Encrypt" and "Decrypt" options
    /// using the colorful theme. The selection determines which files
    /// are shown (encrypted vs unencrypted) and the processing pipeline used.
    ///
    /// # Returns
    ///
    /// The selected ProcessorMode (Encrypt or Decrypt).
    ///
    /// # Errors
    ///
    /// Returns an error if the dialog fails to display or user input fails.
    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        // Get all available modes from the ProcessorMode enum.
        // ALL is a const slice containing [Encrypt, Decrypt].
        let modes = ProcessorMode::ALL;

        // Create display names for the menu.
        // Each mode has a label() method returning "Encrypt" or "Decrypt".
        // This creates a Vec<&str> for the dialoguer Select items.
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        // Create and configure the selection dialog.
        // Select::with_theme() uses our colorful theme for consistent styling.
        // .with_prompt() sets the question displayed above the menu.
        // .items() provides the options to select from.
        // .default(0) pre-selects the first option (Encrypt).
        // .interact() displays the dialog and waits for user input.
        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&display_names)
            .default(0)
            .interact()
            // Map any interaction errors to more descriptive messages.
            .map_err(|e| anyhow!("mode selection failed: {e}"))?;

        // Convert the selected index back to the corresponding ProcessorMode.
        // The index corresponds to the position in ProcessorMode::ALL.
        Ok(modes[idx])
    }

    /// Prompts user to select a file from the provided list.
    ///
    /// Displays discovered files in a numbered list and allows the user
    /// to select one. The file list is typically generated by File::discover()
    /// filtered by the processing mode (encrypted files for decryption, etc.).
    ///
    /// # Arguments
    ///
    /// * `files` - List of File objects to display for selection.
    ///   Must be non-empty; caller should handle the "no files" case.
    ///
    /// # Returns
    ///
    /// The PathBuf of the selected file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No files are available (empty list)
    /// - The dialog fails to display
    /// - User selection fails
    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        // Validate that we have files to select from.
        // This should be checked before calling, but we guard anyway.
        ensure!(!files.is_empty(), "no files available for selection");

        // Extract display names from the file list.
        // We show just the filename, not the full path, for readability.
        // For each file: get file_name(), convert to String, or use full path as fallback.
        let display_names: Vec<String> = files
            .iter()
            .map(|f| f.path().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.path().display().to_string()))
            .collect();

        // Create and configure the file selection dialog.
        // Select::with_theme() uses our colorful theme.
        // .with_prompt() sets the question text.
        // .items() provides the file names for display.
        // .default(0) pre-selects the first file.
        // .interact() shows the dialog and returns the selected index.
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("file selection failed: {e}"))?;

        // Return the path of the selected file.
        // We convert PathBuf to ensure we return an owned value.
        Ok(files[selection].path().to_path_buf())
    }

    /// Prompts for confirmation if output file already exists.
    ///
    /// Prevents accidental data loss by asking the user to confirm
    /// before overwriting an existing file.
    ///
    /// # Arguments
    ///
    /// * `path` - The output file path that already exists.
    ///
    /// # Returns
    ///
    /// true if the user confirms they want to overwrite, false if they decline.
    ///
    /// # Errors
    ///
    /// Returns an error if the confirmation dialog fails.
    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        // Extract just the filename for display (cleaner prompt).
        // file_name() returns Some if there's a final path component.
        // to_string_lossy() converts to UTF-8 String, handling invalid characters.
        // unwrap_or_else() falls back to full path display if no filename.
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        // Delegate to the internal confirm() helper with a formatted prompt.
        self.confirm(&format!("Output file {} already exists. Overwrite?", filename))
    }

    /// Prompts for confirmation to delete the source file.
    ///
    /// After successful encryption/decryption, offers to delete the source file.
    /// The file_type parameter makes the prompt clearer ("original" or "encrypted").
    ///
    /// # Arguments
    ///
    /// * `path` - The source file that could be deleted.
    /// * `file_type` - Description of file type: "original" for encryption, "encrypted" for decryption.
    ///
    /// # Returns
    ///
    /// true if the user confirms deletion, false if they decline.
    ///
    /// # Errors
    ///
    /// Returns an error if the confirmation dialog fails.
    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        // Extract filename for display (same pattern as confirm_file_overwrite).
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        // Format the confirmation prompt with the file type and name.
        // Example: "Delete original file document.txt?"
        self.confirm(&format!("Delete {} file {}?", file_type, filename))
    }

    /// Internal password prompt with validation.
    ///
    /// Displays a masked password input using the configured theme.
    /// Validates that the password is not empty/whitespace and meets
    /// the minimum length requirement.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt text to display (e.g., "Enter encryption password").
    ///
    /// # Returns
    ///
    /// The validated password string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails (empty, whitespace, too short)
    /// - The prompt interaction fails
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        // Create a password input with the configured theme.
        // Password::with_theme() uses ColorfulTheme for styled output.
        // .with_prompt() sets the displayed question.
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            // Add validation closure that runs after input.
            // Returns Ok(()) if valid, error if invalid.
            .validate_with(|input: &String| -> Result<()> {
                // Check that password is not empty or whitespace-only.
                // trim() removes leading/trailing whitespace.
                ensure!(!input.trim().is_empty(), "password cannot be empty or whitespace only");
                // Check minimum length requirement.
                ensure!(input.len() >= self.password_min_length, "password must be at least {} characters long", self.password_min_length);
                Ok(())
            })
            // .interact() displays the prompt and waits for input.
            // The password is masked (not displayed) for security.
            .interact()
            // Map errors to descriptive messages.
            .map_err(|e| anyhow!("password input failed: {e}"))
    }

    /// Internal confirmation prompt helper.
    ///
    /// Displays a yes/no confirmation dialog with the given prompt.
    /// Default is false (user must explicitly confirm).
    ///
    /// # Arguments
    ///
    /// * `prompt` - The confirmation question to display.
    ///
    /// # Returns
    ///
    /// true if user selects Yes, false if user selects No.
    ///
    /// # Errors
    ///
    /// Returns an error if the dialog fails.
    fn confirm(&self, prompt: &str) -> Result<bool> {
        // Create a confirmation dialog with the configured theme.
        // Confirm::with_theme() uses ColorfulTheme for styled output.
        // .with_prompt() sets the question text.
        // .default(false) means pressing Enter selects No (safer default).
        // .interact() displays the dialog and returns the boolean result.
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            // Map errors to descriptive messages.
            .map_err(|e| anyhow!("confirmation failed: {e}"))
    }
}
