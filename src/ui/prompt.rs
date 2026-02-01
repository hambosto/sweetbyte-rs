use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::validator::Validation;
use inquire::{Confirm, Password, PasswordDisplayMode, Select};

use crate::file::File;
use crate::types::ProcessorMode;

pub struct Prompt {
    password_min_length: usize,
}

impl Prompt {
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length }
    }

    fn prompt_password(&self, message: &str, with_confirmation: bool) -> Result<String> {
        let min_length = self.password_min_length;
        let validator = move |input: &str| {
            if input.trim().is_empty() {
                Ok(Validation::Invalid("empty password".into()))
            } else if input.len() < min_length {
                Ok(Validation::Invalid(format!("password < {} chars", min_length).into()))
            } else {
                Ok(Validation::Valid)
            }
        };

        let mut prompt = Password::new(message).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        if with_confirmation {
            prompt = prompt.with_custom_confirmation_message("Confirm password").with_custom_confirmation_error_message("passwords mismatch");
        } else {
            prompt = prompt.without_confirmation();
        }

        prompt.prompt().context("input password")
    }

    pub fn prompt_encryption_password(&self) -> Result<String> {
        self.prompt_password("Enter encryption password", true)
    }

    pub fn prompt_decryption_password(&self) -> Result<String> {
        self.prompt_password("Enter decryption password", false)
    }

    pub fn select_processing_mode(&self) -> Result<ProcessorMode> {
        let modes = ProcessorMode::ALL;
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        self.select_from_list("Select operation", &display_names).map(|idx| modes[idx])
    }

    pub fn select_file(&self, files: &[File]) -> Result<PathBuf> {
        if files.is_empty() {
            anyhow::bail!("no files available for selection");
        }

        let display_names: Vec<String> = files.iter().map(|f| Self::get_display_name(f.path())).collect();
        let idx = self.select_from_list("Select file", &display_names)?;

        Ok(files[idx].path().to_path_buf())
    }

    fn select_from_list<T: ToString>(&self, message: &str, items: &[T]) -> Result<usize> {
        let display_names: Vec<String> = items.iter().map(|item| item.to_string()).collect();
        let selection = Select::new(message, display_names.clone()).with_starting_cursor(0).prompt().context("select from list")?;

        Ok(display_names.iter().position(|r| r == &selection).unwrap())
    }

    pub fn confirm_file_overwrite(&self, path: &Path) -> Result<bool> {
        let filename = Self::get_display_name(path);
        self.confirm(&format!("Output file {filename} already exists. Overwrite?"))
    }

    pub fn confirm_file_deletion(&self, path: &Path, file_type: &str) -> Result<bool> {
        let filename = Self::get_display_name(path);
        self.confirm(&format!("Delete {file_type} file {filename}?"))
    }

    fn get_display_name(path: &Path) -> String {
        path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        Confirm::new(prompt).with_default(false).prompt().context("confirm")
    }
}
