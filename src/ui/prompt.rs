use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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

        if password != confirmation {
            anyhow::bail!("passwords mismatch");
        }

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
            .context("select mode")?;

        Ok(modes[idx])
    }

    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        if files.is_empty() {
            anyhow::bail!("no files available for selection");
        }

        let display_names: Vec<String> = files
            .iter()
            .map(|f| f.path().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.path().display().to_string()))
            .collect();

        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select file")
            .items(&display_names)
            .default(0)
            .interact()
            .context("select file")?;

        Ok(files[selection].path().to_path_buf())
    }

    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        self.confirm(&format!("Output file {filename} already exists. Overwrite?"))
    }

    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

        self.confirm(&format!("Delete {file_type} file {filename}?"))
    }

    fn prompt_password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .validate_with(|input: &String| -> Result<()> {
                if input.trim().is_empty() {
                    anyhow::bail!("empty password");
                }

                if input.len() < self.password_min_length {
                    anyhow::bail!("password < {} chars", self.password_min_length);
                }

                Ok(())
            })
            .interact()
            .context("input password")
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::with_theme(&self.theme).with_prompt(prompt).default(false).interact().context("confirm")
    }
}
