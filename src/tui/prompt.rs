use anyhow::{Context, Result};
use inquire::{Confirm, Password, Select};
use std::path::PathBuf;

use crate::types::ProcessorMode;

pub struct PromptInput {
    password_min_length: usize,
}

impl PromptInput {
    /// Creates a new `PromptInput` instance.
    ///
    /// # Arguments
    ///
    /// * `password_min_length` - The minimum length for the password.
    ///
    /// # Returns
    /// A new instance of `PromptInput`.
    pub fn new(password_min_length: usize) -> Self {
        Self {
            password_min_length,
        }
    }

    /// Prompts the user to confirm if they want to overwrite an existing file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the existing file that would be overwritten.
    ///
    /// # Returns
    /// A `Result<bool>` that indicates whether the user confirmed the overwrite (`true`) or not (`false`).
    pub fn confirm_file_overwrite(&self, path: &str) -> Result<bool> {
        self.confirm(&format!("Output file {} already exists. Overwrite?", path))
    }

    /// Prompts the user to enter and confirm an encryption password.
    /// The password must meet the minimum length requirement and match the confirmation.
    ///
    /// # Returns
    /// A `Result<String>` containing the encryption password if successful, or an error if the validation fails.
    pub fn get_encryption_password(&self) -> Result<String> {
        let password = self.get_password("Enter encryption password:")?;

        self.validate_password(&password)?;

        let confirm = self.get_password("Confirm password:")?;
        if password != confirm {
            anyhow::bail!("password mismatch");
        }

        Ok(password)
    }

    /// Prompts the user to enter a decryption password.
    /// The password cannot be empty.
    ///
    /// # Returns
    /// A `Result<String>` containing the decryption password if successful, or an error if the password is empty.
    pub fn get_decryption_password(&self) -> Result<String> {
        let password = self.get_password("Enter decryption password:")?;

        if password.trim().is_empty() {
            anyhow::bail!("password cannot be empty");
        }

        Ok(password)
    }

    /// Prompts the user to confirm if they want to delete a file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file that is being considered for deletion.
    /// * `file_type` - The type of the file (e.g., "source", "destination").
    ///
    /// # Returns
    /// A `Result<bool>` indicating whether the user confirmed the file removal (`true`) or not (`false`).
    pub fn confirm_file_removal(&self, path: &str, file_type: &str) -> Result<bool> {
        let confirm = self.confirm(&format!("Delete {} file {}?", file_type, path))?;
        if !confirm {
            return Ok(false);
        }

        Ok(true)
    }

    /// Prompts the user to select a processing mode (either Encrypt or Decrypt).
    ///
    /// # Returns
    /// A `Result<ProcessorMode>` that indicates the selected processing mode.
    pub fn get_processing_mode(&self) -> Result<ProcessorMode> {
        let mode = self
            .choose(
                "Select operation:",
                &[
                    ProcessorMode::Encrypt.to_string(),
                    ProcessorMode::Decrypt.to_string(),
                ],
            )
            .context("operation selection failed")?;

        match mode.as_str() {
            "Encrypt" => Ok(ProcessorMode::Encrypt),
            "Decrypt" => Ok(ProcessorMode::Decrypt),
            _ => unreachable!(),
        }
    }

    /// Prompts the user to select a file from a list of available files.
    ///
    /// # Arguments
    ///
    /// * `file_list` - A slice of `PathBuf` representing the list of available files.
    ///
    /// # Returns
    /// A `Result<PathBuf>` containing the path of the selected file.
    pub fn choose_file(&self, file_list: &[PathBuf]) -> Result<PathBuf> {
        let file_strings: Vec<String> = file_list
            .iter()
            .map(|p| {
                p.strip_prefix(".")
                    .unwrap_or(p)
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        if file_strings.is_empty() {
            anyhow::bail!("no files available for selection");
        }

        let selected = self.choose("Select file:", &file_strings)?;

        let index = file_strings.iter().position(|s| s == &selected).unwrap();
        Ok(file_list[index].clone())
    }

    /// Prompts the user to enter a password.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to display when asking for the password.
    ///
    /// # Returns
    /// A `Result<String>` containing the entered password.
    fn get_password(&self, message: &str) -> Result<String> {
        Password::new(message)
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
            .context("password prompt failed")
    }

    /// Validates that the password meets the minimum length requirement and is not empty.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to validate.
    ///
    /// # Returns
    /// A `Result<()>` that indicates whether the password is valid or not.
    fn validate_password(&self, password: &str) -> Result<()> {
        if password.len() < self.password_min_length {
            anyhow::bail!(
                "password must be at least {} characters",
                self.password_min_length
            );
        }

        if password.trim().is_empty() {
            anyhow::bail!("password cannot be empty");
        }

        Ok(())
    }

    /// Prompts the user with a yes/no confirmation question.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to display when asking for confirmation.
    ///
    /// # Returns
    /// A `Result<bool>` indicating whether the user confirmed (`true`) or denied (`false`).
    fn confirm(&self, message: &str) -> Result<bool> {
        Confirm::new(message)
            .with_default(false)
            .prompt()
            .context("confirmation failed")
    }

    /// Prompts the user to select an option from a list of choices.
    ///
    /// # Arguments
    ///
    /// * `title` - The prompt message to display when asking for the selection.
    /// * `option_list` - A list of options to choose from.
    ///
    /// # Returns
    /// A `Result<String>` containing the selected option.
    fn choose(&self, title: &str, option_list: &[String]) -> Result<String> {
        if option_list.is_empty() {
            anyhow::bail!("no options available for selection");
        }

        Select::new(title, option_list.to_vec())
            .prompt()
            .context("selection failed")
    }
}
