use anyhow::Result;
use inquire::{Confirm, Password, Select};
use std::path::PathBuf;

/// Prompts the user for a password.
pub fn ask_password(prompt: &str) -> Result<String> {
    Ok(Password::new(prompt)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()?)
}

/// Prompts the user for confirmation (Yes/No).
pub fn ask_confirm(prompt: &str) -> Result<bool> {
    Ok(Confirm::new(prompt).with_default(false).prompt()?)
}

/// Prompts the user to select a processing mode (Encrypt/Decrypt).
pub fn ask_processing_mode() -> Result<crate::types::ProcessorMode> {
    let options = vec!["Encrypt", "Decrypt"];
    let selection = Select::new("Select operation:", options).prompt()?;

    match selection {
        "Encrypt" => Ok(crate::types::ProcessorMode::Encrypt),
        "Decrypt" => Ok(crate::types::ProcessorMode::Decrypt),
        _ => unreachable!(),
    }
}

/// Prompts the user to select a file from a list.
pub fn choose_file(files: &[PathBuf]) -> Result<PathBuf> {
    let file_strings: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let selected = Select::new("Select file to process:", file_strings.clone()).prompt()?;

    // Find the corresponding PathBuf
    let index = file_strings.iter().position(|s| s == &selected).unwrap();
    Ok(files[index].clone())
}
