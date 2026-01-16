use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::types::ProcessorMode;

pub struct Prompt {
    theme: ColorfulTheme,
}

impl Prompt {
    pub fn new() -> Self {
        Self { theme: ColorfulTheme::default() }
    }

    pub fn with_theme(theme: ColorfulTheme) -> Self {
        Self { theme }
    }

    pub fn prompt_encryption_password(&self) -> Result<String> {
        let password = self.prompt_password("Enter encryption password")?;
        let confirmation = self.prompt_password("Confirm password")?;

        if password != confirmation {
            bail!("passwords do not match");
        }

        Ok(password)
    }

    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password")
    }

    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        let options = [ProcessorMode::Encrypt.as_str(), ProcessorMode::Decrypt.as_str()];

        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("mode selection failed: {}", e))?;

        match selection {
            0 => Ok(ProcessorMode::Encrypt),
            1 => Ok(ProcessorMode::Decrypt),
            _ => unreachable!("selection index out of bounds"),
        }
    }

    pub fn select_file(&self, files: &[PathBuf]) -> Result<PathBuf> {
        if files.is_empty() {
            bail!("no files available for selection");
        }

        let display_names: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("file selection failed: {}", e))?;

        Ok(files[selection].clone())
    }

    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        self.confirm(&format!("Output file {} already exists. Overwrite?", path.display()))
    }

    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        self.confirm(&format!("Delete {} file {}?", file_type, path.display()))
    }

    fn prompt_password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .validate_with(Self::validate_password)
            .interact()
            .map_err(|e| anyhow!("password input failed: {}", e))
    }

    fn validate_password(input: &String) -> Result<()> {
        if input.trim().is_empty() {
            bail!("password cannot be empty or whitespace only");
        }

        if input.len() < PASSWORD_MIN_LENGTH {
            bail!("password must be at least {} characters long", PASSWORD_MIN_LENGTH);
        }

        Ok(())
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|e| anyhow!("confirmation failed: {}", e))
    }
}

impl Default for Prompt {
    fn default() -> Self {
        Self::new()
    }
}
