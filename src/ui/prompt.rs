use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::files::Files;
use crate::types::{PathName, Processing};

pub struct Prompt {
    min_password_len: usize,
    default_overwrite: bool,
    default_delete: bool,
    filter_mode: bool,
}

impl Prompt {
    pub fn new(min_password_len: usize, filter_mode: bool) -> Self {
        Self { min_password_len, default_overwrite: false, default_delete: false, filter_mode }
    }

    pub fn password(&self, processing: Processing) -> Result<String> {
        let min = self.min_password_len;
        let validate = move |s: &String| (s.len() >= min).then_some(()).ok_or_else(|| format!("Password must be at least {} characters", min));

        let (message, confirm_message) = match processing {
            Processing::Encryption => ("Enter encryption password", Some("Confirm password")),
            Processing::Decryption => ("Enter decryption password", None),
        };

        let password = cliclack::password(message).validate(validate).interact().context("password input failed")?;
        if let Some(message) = confirm_message {
            let confirmed = cliclack::password(message).validate(validate).interact().context("password confirm failed")?;
            anyhow::ensure!(password == confirmed, "passwords mismatch");
        }

        Ok(password)
    }

    pub fn processing_mode(&self) -> Result<Processing> {
        let mut select = cliclack::select("Select operation");
        for m in Processing::iter() {
            select = select.item(m, m.to_string(), "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("operation selection failed")
    }

    pub fn file(&self, files: &[Files]) -> Result<PathBuf> {
        let mut select = cliclack::select("Select file");
        for f in files {
            select = select.item(f.path().to_path_buf(), f.path().name(), "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("file selection failed")
    }

    pub fn overwrite(&self, path: &Path) -> Result<bool> {
        cliclack::confirm(format!("Output file {} already exists. Overwrite?", path.name()))
            .initial_value(self.default_overwrite)
            .interact()
            .context("overwrite confirmation failed")
    }

    pub fn delete(&self, path: &Path, processing: Processing) -> Result<bool> {
        let kind = match processing {
            Processing::Encryption => "encrypted",
            Processing::Decryption => "decrypted",
        };

        cliclack::confirm(format!("Delete {} file {}?", kind, path.name()))
            .initial_value(self.default_delete)
            .interact()
            .context("delete confirmation failed")
    }
}
