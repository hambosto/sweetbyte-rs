use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select};
use strum::IntoEnumIterator;

use crate::file::File;
use crate::types::ProcessorMode;

pub struct Prompt {
    password_min_length: usize,
}

impl Prompt {
    pub fn new(password_min_length: usize) -> Self {
        Self { password_min_length }
    }

    pub fn prompt_encryption_password(&self) -> Result<String> {
        Self::prompt_password("Enter encryption password", true, self.password_min_length)
    }

    pub fn prompt_decryption_password(&self) -> Result<String> {
        Self::prompt_password("Enter decryption password", false, self.password_min_length)
    }

    fn prompt_password(message: &str, with_confirmation: bool, password_min_length: usize) -> Result<String> {
        let validator = inquire::min_length!(password_min_length);
        let mut prompt = Password::new(message).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        if with_confirmation {
            prompt = prompt.with_custom_confirmation_message("Confirm password").with_custom_confirmation_error_message("passwords mismatch");
        } else {
            prompt = prompt.without_confirmation();
        }

        prompt.prompt().context("input password")
    }

    pub fn select_processing_mode() -> Result<ProcessorMode> {
        let modes: Vec<ProcessorMode> = ProcessorMode::iter().collect();
        let display_names: Vec<&str> = modes.iter().map(|m| m.label()).collect();

        Self::select_from_list("Select operation", &display_names).map(|idx| modes[idx])
    }

    pub fn select_file(files: &[File]) -> Result<PathBuf> {
        if files.is_empty() {
            anyhow::bail!("no files available for selection");
        }

        let display_names: Vec<String> = files.iter().map(|f| Self::get_display_name(f.path())).collect();
        let idx = Self::select_from_list("Select file", &display_names)?;

        Ok(files[idx].path().to_path_buf())
    }

    fn select_from_list<T: ToString>(message: &str, items: &[T]) -> Result<usize> {
        let display_names: Vec<String> = items.iter().map(|item| item.to_string()).collect();
        let selection = Select::new(message, display_names.clone()).with_starting_cursor(0).prompt().context("select from list")?;

        display_names.into_iter().position(|name| name == selection).ok_or_else(|| anyhow::anyhow!("selection not found"))
    }

    pub fn confirm_file_overwrite(path: &Path) -> Result<bool> {
        let filename = Self::get_display_name(path);
        Self::confirm(&format!("Output file {filename} already exists. Overwrite?"))
    }

    pub fn confirm_file_deletion(path: &Path, file_type: &str) -> Result<bool> {
        let filename = Self::get_display_name(path);
        Self::confirm(&format!("Delete {file_type} file {filename}?"))
    }

    fn get_display_name(path: &Path) -> String {
        path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
    }

    fn confirm(prompt: &str) -> Result<bool> {
        Confirm::new(prompt).with_default(false).prompt().context("confirm")
    }
}
