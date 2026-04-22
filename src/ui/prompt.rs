use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select};

use crate::files::Files;
use crate::types::Processing;

pub struct Prompt {
    min_password_len: usize,
    default_overwrite: bool,
    default_delete: bool,
    starting_cursor: usize,
}

impl Prompt {
    pub fn new(min_password_len: usize) -> Self {
        Self { min_password_len, default_overwrite: false, default_delete: false, starting_cursor: 0 }
    }

    pub fn password(&self, processing: Processing) -> Result<String> {
        let (message, confirm) = match processing {
            Processing::Encryption => ("Enter encryption password", Some(("Confirm password", "Passwords missmatch"))),
            Processing::Decryption => ("Enter decryption password", None),
        };

        let validator = inquire::min_length!(self.min_password_len);
        let base = Password::new(message).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);
        let prompt = match confirm {
            Some((message, error)) => base.with_custom_confirmation_message(message).with_custom_confirmation_error_message(error),
            None => base.without_confirmation(),
        };

        prompt.prompt().context("failed to read password")
    }

    pub fn processing_mode(&self) -> Result<Processing> {
        let modes: Vec<Processing> = Processing::iter().collect();
        let labels: Vec<String> = modes.iter().map(|m| m.to_string()).collect();

        let choice = Select::new("Select operation", labels)
            .with_starting_cursor(self.starting_cursor)
            .prompt()
            .context("failed to read selection")?;

        modes.into_iter().find(|m| m.to_string() == choice).context("invalid selection")
    }

    pub fn file(&self, files: &[Files]) -> Result<PathBuf> {
        anyhow::ensure!(!files.is_empty(), "no files available");

        let labels: Vec<String> = files.iter().map(|f| filename(f.path())).collect();
        let choice = Select::new("Select file", labels)
            .with_starting_cursor(self.starting_cursor)
            .prompt()
            .context("failed to read selection")?;

        files
            .iter()
            .position(|f| filename(f.path()) == choice)
            .and_then(|i| files.get(i))
            .map(|f| f.path().to_path_buf())
            .context("invalid selection")
    }

    pub fn overwrite(&self, path: &Path) -> Result<bool> {
        let message = format!("Output file {} already exists. Overwrite?", filename(path));
        Confirm::new(&message).with_default(self.default_overwrite).prompt().context("failed to read confirmation")
    }

    pub fn delete(&self, path: &Path, processing: Processing) -> Result<bool> {
        let kind = match processing {
            Processing::Encryption => "encrypted",
            Processing::Decryption => "decrypted",
        };
        let message = format!("Delete {} file {}?", kind, filename(path));
        Confirm::new(&message).with_default(self.default_delete).prompt().context("failed to read confirmation")
    }
}

fn filename(path: &Path) -> String {
    path.file_name().unwrap_or(path.as_os_str()).to_string_lossy().into()
}
