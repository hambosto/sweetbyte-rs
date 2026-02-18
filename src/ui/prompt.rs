use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
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
        let mut p = Password::new(msg).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        if confirm {
            p = p.with_custom_confirmation_message("Confirm password").with_custom_confirmation_error_message("passwords mismatch");
        } else {
            p = p.without_confirmation();
        }

        p.prompt().context("input password")
    }

    pub fn mode() -> Result<ProcessorMode> {
        let modes: Vec<_> = ProcessorMode::iter().collect();
        let labels: Vec<_> = modes.iter().map(|m| m.label()).collect();
        select("Select operation", &labels).map(|i| modes[i])
    }

    pub fn file(files: &[File]) -> Result<PathBuf> {
        if files.is_empty() {
            return Err(anyhow!("no files available"));
        }

        let labels: Vec<_> = files.iter().map(|f| filename(f.path())).collect();
        select("Select file", &labels).map(|i| files[i].path().to_path_buf())
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

fn select(msg: &str, items: &[impl ToString]) -> Result<usize> {
    let labels: Vec<_> = items.iter().map(ToString::to_string).collect();
    let choice = Select::new(msg, labels.clone()).with_starting_cursor(0).prompt().context("selection")?;

    labels.into_iter().position(|l| l == choice).ok_or_else(|| anyhow!("invalid selection"))
}

fn confirm(msg: &str) -> Result<bool> {
    Confirm::new(msg).with_default(false).prompt().context("confirmation")
}
