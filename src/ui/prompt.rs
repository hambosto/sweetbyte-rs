use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select};
use strum::IntoEnumIterator;

use crate::file::File;
use crate::types::ProcessorMode;

pub struct Prompt {
    min_len: usize,
}

impl Prompt {
    pub fn new(min_len: usize) -> Self {
        Self { min_len }
    }

    pub fn encrypt_password(&self) -> Result<String> {
        self.password("Enter encryption password", true)
    }

    pub fn decrypt_password(&self) -> Result<String> {
        self.password("Enter decryption password", false)
    }

    fn password(&self, msg: &str, confirm: bool) -> Result<String> {
        let validator = inquire::min_length!(self.min_len);
        let mut password = Password::new(msg).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        if confirm {
            password = password
                .with_custom_confirmation_message("Confirm password")
                .with_custom_confirmation_error_message("passwords mismatch");
        } else {
            password = password.without_confirmation();
        }

        password.prompt().context("Failed to read password")
    }

    pub fn mode() -> Result<ProcessorMode> {
        select("Select operation", ProcessorMode::iter())
    }

    pub fn file(files: &[File]) -> Result<PathBuf> {
        anyhow::ensure!(!files.is_empty(), "No files available");
        select_by("Select file", files, |f: &File| filename(f.path())).map(|f| f.path().to_path_buf())
    }

    pub fn overwrite(path: &Path) -> Result<bool> {
        confirm(&format!("Output file {} already exists. Overwrite?", filename(path)))
    }

    pub fn delete(path: &Path, kind: &str) -> Result<bool> {
        confirm(&format!("Delete {} file {}?", kind, filename(path)))
    }
}

fn filename(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

fn select<T>(msg: &str, items: impl IntoIterator<Item = T>) -> Result<T>
where
    T: ToString,
{
    let items: Vec<T> = items.into_iter().collect();
    let labels: Vec<String> = items.iter().map(ToString::to_string).collect();

    let idx = Select::new(msg, labels.clone())
        .with_starting_cursor(0)
        .prompt()
        .context("Failed to read user selection")
        .and_then(|choice| labels.iter().position(|l| l == &choice).context("Invalid user selection"))?;

    items.into_iter().nth(idx).context("Invalid user selection")
}

fn select_by<'a, T, F, D>(msg: &str, items: &'a [T], key: F) -> Result<&'a T>
where
    F: Fn(&T) -> D,
    D: ToString,
{
    let labels: Vec<String> = items.iter().map(|i| key(i).to_string()).collect();

    let idx = Select::new(msg, labels.clone())
        .with_starting_cursor(0)
        .prompt()
        .context("Failed to read user selection")
        .and_then(|choice| labels.iter().position(|l| l == &choice).context("Invalid user selection"))?;

    items.get(idx).context("Invalid user selection")
}

fn confirm(msg: &str) -> Result<bool> {
    Confirm::new(msg).with_default(false).prompt().context("Failed to read user confirmation")
}
