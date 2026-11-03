use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::core::{FileItem, Operation, Secret};

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

        loop {
            let mut password = cliclack::password(prompt).validate(validate).interact().context("failed to read password")?;

            if let Some(confirmation) = confirm_prompt {
                let mut confirmation_password = cliclack::password(confirmation).validate(validate).interact().context("failed to read confirm password")?;

                if confirmation_password != password {
                    password.zeroize();
                    confirmation_password.zeroize();

                    cliclack::log::error("Password mismatch").context("failed to display error")?;
                    continue;
                }

                confirmation_password.zeroize();
            }

            let secret = Secret::from(Sha256::digest(password.as_bytes()).to_vec());
            password.zeroize();

            break Ok(secret);
        }
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

    pub(crate) fn select_file(&self, entries: &[FileItem]) -> Result<PathBuf> {
        let mut select = cliclack::select("Select file");
        for entry in entries {
            select = select.item(entry.path().into(), entry.name(), humansize::format_size(entry.size(), humansize::DECIMAL));
        }

        if self.filter_mode {
            select = select.filter_mode();
        }

        select.interact().context("failed to select file")
    }

    pub(crate) fn confirm_overwrite(&self, file_name: &str) -> Result<bool> {
        cliclack::confirm(format!("Output file {file_name} already exists. Overwrite?"))
            .initial_value(self.default_overwrite)
            .interact()
            .context("failed to confirm overwrite")
    }

    pub(crate) fn confirm_deletion(&self, file_name: &str, operation: Operation) -> Result<bool> {
        let action = match operation {
            Operation::Encryption => "encrypted",
            Operation::Decryption => "decrypted",
        };

        cliclack::confirm(format!("Delete {action} file {file_name}?"))
            .initial_value(self.default_delete)
            .interact()
            .context("failed to confirm deletion")
    }
}
