use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select};

use crate::files::Files;
use crate::types::ProcessorMode;

pub struct Ask {
    min_password_len: usize,
    default_overwrite: bool,
    default_delete: bool,
    starting_cursor: usize,
}

impl Ask {
    pub fn new(min_password_len: usize) -> Self {
        Self { min_password_len, default_overwrite: false, default_delete: false, starting_cursor: 0 }
    }

    pub fn password(&self, processing: ProcessorMode) -> Result<String> {
        let message = match processing {
            ProcessorMode::Encryption => "Enter encryption password",
            ProcessorMode::Decryption => "Enter decryption password",
        };

        let validator = inquire::min_length!(self.min_password_len);
        let password = Password::new(message).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        let prompt = match processing {
            ProcessorMode::Encryption => password
                .with_custom_confirmation_message("Confirm password")
                .with_custom_confirmation_error_message("Passwords mismatch"),
            ProcessorMode::Decryption => password.without_confirmation(),
        };

        prompt.prompt().context("Failed to read password")
    }

    pub fn mode(&self) -> Result<ProcessorMode> {
        let modes: Vec<ProcessorMode> = ProcessorMode::iter().collect();
        let labels: Vec<String> = modes.iter().map(|m| m.to_string()).collect();

        let choice = Select::new("Select operation", labels)
            .with_starting_cursor(self.starting_cursor)
            .prompt()
            .context("Failed to read selection")?;

        modes.into_iter().find(|m| m.to_string() == choice).context("Invalid selection")
    }

    pub fn file(&self, files: &[Files]) -> Result<PathBuf> {
        anyhow::ensure!(!files.is_empty(), "No files available");

        let labels: Vec<String> = files.iter().map(|f| filename(f.path())).collect();
        let choice = Select::new("Select file", labels)
            .with_starting_cursor(self.starting_cursor)
            .prompt()
            .context("Failed to read selection")?;

        files
            .iter()
            .position(|f| filename(f.path()) == choice)
            .and_then(|i| files.get(i))
            .map(|f| f.path().to_path_buf())
            .context("Invalid selection")
    }

    pub fn overwrite(&self, path: &Path) -> Result<bool> {
        let message = format!("Output file {} already exists. Overwrite?", filename(path));
        Confirm::new(&message).with_default(self.default_overwrite).prompt().context("Failed to read confirmation")
    }

    pub fn delete(&self, path: &Path, mode: ProcessorMode) -> Result<bool> {
        let kind = match mode {
            ProcessorMode::Encryption => "encrypted",
            ProcessorMode::Decryption => "decrypted",
        };
        let message = format!("Delete {} file {}?", kind, filename(path));
        Confirm::new(&message).with_default(self.default_delete).prompt().context("Failed to read confirmation")
    }
}

fn filename(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}
