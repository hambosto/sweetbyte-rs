use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::files::Files;
use crate::pipeline::Operation;
use crate::secret::Secret;

pub(crate) struct Input {
    min_password_len: usize,
    default_overwrite: bool,
    default_delete: bool,
    filter_mode: bool,
}

impl Input {
    pub(crate) fn new(min_password_len: usize, filter_mode: bool) -> Self {
        Self { min_password_len, default_overwrite: false, default_delete: false, filter_mode }
    }

    pub(crate) fn password(&self, operation: Operation) -> Result<Secret> {
        let min = self.min_password_len;
        let validate = move |s: &String| (s.len() >= min).then_some(()).ok_or_else(|| format!("password must be at least {min} characters"));

        let (message, confirm_message) = match operation {
            Operation::Encryption => ("Enter encryption password", Some("Confirm password")),
            Operation::Decryption => ("Enter decryption password", None),
        };

        let password = cliclack::password(message).validate(validate).interact().context("failed to read password")?;
        if let Some(message) = confirm_message {
            let confirmed = cliclack::password(message).validate(validate).interact().context("failed to confirm password")?;
            if password != confirmed {
                anyhow::bail!("passwords do not match");
            }
        }

        Ok(Secret::new(password.as_bytes().to_vec()))
    }

    pub(crate) fn operation_mode(&self) -> Result<Operation> {
        let mut select = cliclack::select("Select operation");
        for m in Operation::iter() {
            select = select.item(m, m.to_string(), "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("failed to select operation")
    }

    pub(crate) fn file(&self, files: &[Files]) -> Result<PathBuf> {
        let mut select = cliclack::select("Select file");
        for f in files {
            select = select.item(f.path().to_path_buf(), f.name(), "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("failed to select file")
    }

    pub(crate) fn overwrite(&self, file: &Files) -> Result<bool> {
        cliclack::confirm(format!("Output file {} already exists. Overwrite?", file.name()))
            .initial_value(self.default_overwrite)
            .interact()
            .context("failed to confirm overwrite")
    }

    pub(crate) fn delete(&self, file: &Files, operation: Operation) -> Result<bool> {
        let process = match operation {
            Operation::Encryption => "encrypted",
            Operation::Decryption => "decrypted",
        };

        cliclack::confirm(format!("Delete {} file {}?", process, file.name()))
            .initial_value(self.default_delete)
            .interact()
            .context("failed to confirm deletion")
    }
}
