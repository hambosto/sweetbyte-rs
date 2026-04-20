use crate::types::ProcessorMode;
use crate::{file::File, types::Processing};
use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select};
use std::path::{Path, PathBuf};

struct PasswordPrompt {
    message: String,
    min_len: usize,
    processing: Processing,
}

impl PasswordPrompt {
    fn new(message: impl Into<String>, min_len: usize, processing: Processing) -> Self {
        Self { message: message.into(), min_len, processing }
    }

    fn ask(&self) -> Result<String> {
        let validator = inquire::min_length!(self.min_len);
        let prompt = Password::new(&self.message).with_display_mode(PasswordDisplayMode::Masked).with_validator(validator);

        let password = match self.processing {
            Processing::Encryption => prompt.with_custom_confirmation_message("Confirm password").with_custom_confirmation_error_message("Passwords mismatch"),
            Processing::Decryption => prompt.without_confirmation(),
        };

        password.prompt().context("Failed to read password")
    }
}

struct SelectPrompt {
    message: String,
}

impl SelectPrompt {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    fn ask<T: ToString>(&self, items: impl IntoIterator<Item = T>) -> Result<T> {
        let items: Vec<T> = items.into_iter().collect();
        let labels: Vec<String> = items.iter().map(ToString::to_string).collect();
        let idx = self.resolve_index(&labels)?;
        items.into_iter().nth(idx).context("Invalid selection")
    }

    fn ask_ref<T, F, D>(&self, items: &[T], key: F) -> Result<usize>
    where
        F: Fn(&T) -> D,
        D: ToString,
    {
        let labels: Vec<String> = items.iter().map(|i| key(i).to_string()).collect();
        self.resolve_index(&labels)
    }

    fn resolve_index(&self, labels: &[String]) -> Result<usize> {
        Select::new(&self.message, labels.to_vec())
            .with_starting_cursor(0)
            .prompt()
            .context("Failed to read selection")
            .and_then(|choice| labels.iter().position(|l| l == &choice).context("Invalid selection"))
    }
}

struct ConfirmPrompt {
    message: String,
}

impl ConfirmPrompt {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    fn ask(&self) -> Result<bool> {
        Confirm::new(&self.message).with_default(false).prompt().context("Failed to read confirmation")
    }
}

pub struct Prompt {
    min_len: usize,
}

impl Prompt {
    #[must_use] 
    pub fn new(min_len: usize) -> Self {
        Self { min_len }
    }

    pub fn password(&self, processing: &Processing) -> Result<String> {
        let message = match processing {
            Processing::Encryption => "Enter encryption password",
            Processing::Decryption => "Enter decryption password",
        };

        PasswordPrompt::new(message, self.min_len, *processing).ask()
    }

    pub fn mode(&self) -> Result<ProcessorMode> {
        SelectPrompt::new("Select operation").ask(ProcessorMode::iter())
    }

    pub fn file(&self, files: &[File]) -> Result<PathBuf> {
        anyhow::ensure!(!files.is_empty(), "No files available");
        let idx = SelectPrompt::new("Select file").ask_ref(files, |f: &File| filename(f.path()))?;
        files.get(idx).map(|f| f.path().to_path_buf()).context("Invalid selection")
    }

    pub fn overwrite(&self, path: &Path) -> Result<bool> {
        ConfirmPrompt::new(format!("Output file {} already exists. Overwrite?", filename(path))).ask()
    }

    pub fn delete(&self, path: &Path, kind: &str) -> Result<bool> {
        ConfirmPrompt::new(format!("Delete {} file {}?", kind, filename(path))).ask()
    }
}

fn filename(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}
