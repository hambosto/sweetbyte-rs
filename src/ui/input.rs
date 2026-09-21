use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::core::{Operation, Secret};
use crate::fs::FileHandle;

pub(crate) struct Prompt {
    password_len: usize,
    default_overwrite: bool,
    default_delete: bool,
    filter_mode: bool,
}

impl Prompt {
    pub(crate) fn new(password_len: usize, filter_mode: bool) -> Self {
        Self { password_len, default_overwrite: false, default_delete: false, filter_mode }
    }

    pub(crate) fn read_password(&self, operation: Operation) -> Result<Secret> {
        let minimum = self.password_len;
        let validate = move |s: &String| (s.len() >= minimum).then_some(()).ok_or("password too short");

        let (prompt, confirm_prompt) = match operation {
            Operation::Encryption => ("Enter encryption password", Some("Confirm password")),
            Operation::Decryption => ("Enter decryption password", None),
        };

        let password = cliclack::password(prompt).validate(validate).interact().context("failed to read password")?;
        if let Some(confirm_prompt) = confirm_prompt {
            let confirmed = cliclack::password(confirm_prompt).validate(validate).interact().context("failed to confirm password")?;
            if password != confirmed {
                anyhow::bail!("password mismatch");
            }
        }

        Ok(Secret::new(Sha256::digest(password.as_bytes()).to_vec()))
    }

    pub(crate) fn select_operation(&self) -> Result<Operation> {
        let mut select = cliclack::select("Select operation");
        for op in Operation::all() {
            select = select.item(op, op, "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("failed to select operation")
    }

    pub(crate) fn select_file(&self, files: &[FileHandle]) -> Result<PathBuf> {
        let mut select = cliclack::select("Select file");
        for file in files {
            select = select.item(file.path().to_path_buf(), file.name(), "");
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("failed to select file")
    }

    pub(crate) fn confirm_overwrite(&self, file: &FileHandle) -> Result<bool> {
        cliclack::confirm(format!("Output file {} already exists. Overwrite?", file.name()))
            .initial_value(self.default_overwrite)
            .interact()
            .context("failed to confirm overwrite")
    }

    pub(crate) fn confirm_deletion(&self, file: &FileHandle, operation: Operation) -> Result<bool> {
        let action = match operation {
            Operation::Encryption => "encrypted",
            Operation::Decryption => "decrypted",
        };

        cliclack::confirm(format!("Delete {} file {}?", action, file.name()))
            .initial_value(self.default_delete)
            .interact()
            .context("failed to confirm deletion")
    }
}
