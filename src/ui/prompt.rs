use anyhow::{Result, anyhow, bail};
use dialoguer::{Confirm, Password, Select, theme::ColorfulTheme};
use std::path::{Path, PathBuf};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::types::ProcessorMode;

pub fn get_encryption_password() -> Result<String> {
    let password: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter encryption password")
        .interact()
        .map_err(|e| anyhow!("password input failed: {}", e))?;

    if password.len() < PASSWORD_MIN_LENGTH {
        bail!(
            "password must be at least {} characters",
            PASSWORD_MIN_LENGTH
        );
    }

    if password.trim().is_empty() {
        bail!("password cannot be empty");
    }

    let confirm: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Confirm password")
        .interact()
        .map_err(|e| anyhow!("password confirmation failed: {}", e))?;

    if password != confirm {
        bail!("passwords do not match");
    }

    Ok(password)
}

pub fn get_decryption_password() -> Result<String> {
    let password: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter decryption password")
        .interact()
        .map_err(|e| anyhow!("password input failed: {}", e))?;

    if password.trim().is_empty() {
        bail!("password cannot be empty");
    }

    Ok(password)
}

pub fn confirm_overwrite(path: &Path) -> Result<bool> {
    let result = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Output file {} already exists. Overwrite?",
            path.display()
        ))
        .default(false)
        .interact()
        .map_err(|e| anyhow!("confirmation failed: {}", e))?;

    Ok(result)
}

pub fn confirm_removal(path: &Path, file_type: &str) -> Result<bool> {
    let result = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Delete {} file {}?", file_type, path.display()))
        .default(false)
        .interact()
        .map_err(|e| anyhow!("confirmation failed: {}", e))?;

    Ok(result)
}

pub fn get_processing_mode() -> Result<ProcessorMode> {
    let options = vec!["Encrypt", "Decrypt"];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select operation")
        .items(&options)
        .default(0)
        .interact()
        .map_err(|e| anyhow!("selection failed: {}", e))?;

    match selection {
        0 => Ok(ProcessorMode::Encrypt),
        1 => Ok(ProcessorMode::Decrypt),
        _ => bail!("invalid selection"),
    }
}

pub fn choose_file(files: &[PathBuf]) -> Result<PathBuf> {
    if files.is_empty() {
        bail!("no files available");
    }

    let display_names: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select file")
        .items(&display_names)
        .default(0)
        .interact()
        .map_err(|e| anyhow!("selection failed: {}", e))?;

    Ok(files[selection].clone())
}
