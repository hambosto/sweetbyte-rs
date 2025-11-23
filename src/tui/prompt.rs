use anyhow::Result;
use inquire::{Confirm, Password, Select};

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
pub fn choose_file(files: &[String]) -> Result<String> {
    Ok(Select::new("Select file to process:", files.to_vec()).prompt()?)
}
