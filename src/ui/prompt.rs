use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Password, Select};

use crate::file::File;
use crate::types::ProcessorMode;

pub struct Prompt {
    password_min_length: usize,

    theme: ColorfulTheme,
}

impl Prompt {
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length, theme: ColorfulTheme::default() }
    }

    pub fn prompt_encryption_password(&self) -> Result<String> {
        let password = self.prompt_password("Enter encryption password")?;

        let confirmation = self.prompt_password("Confirm password")?;

        ensure!(password == confirmation, "password do not math");

        Ok(password)
    }

    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password")
    }

    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        let modes = ProcessorMode::ALL;
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select operation")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("mode selection failed: {e}"))?;

        Ok(modes[idx])
    }

    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        ensure!(!files.is_empty(), "no files available for selection");

        let display_names: Vec<String> = files.iter().map(|f| f.path().display().to_string()).collect();

        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("file selection failed: {e}"))?;

        Ok(files[selection].path().to_path_buf())
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
            .validate_with(|input: &String| -> Result<()> {
                ensure!(!input.trim().is_empty(), "password cannot be empty or whitespace only");
                ensure!(input.len() >= self.password_min_length, "password must be at least {} characters long", self.password_min_length);

                Ok(())
            })
            .interact()
            .map_err(|e| anyhow!("password input failed: {e}"))
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|e| anyhow!("confirmation failed: {e}"))
    }
}
