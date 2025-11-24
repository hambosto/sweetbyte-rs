pub mod compression;
pub mod config;
pub mod crypto;
pub mod encoding;
pub mod file;
pub mod header;
pub mod padding;
pub mod processor;
pub mod stream;
pub mod tui;
pub mod types;
pub mod utils;

use anyhow::{Result, anyhow};
use types::ProcessorMode;

fn main() -> Result<()> {
    // 1. Show welcome banner
    tui::print_banner();

    // 2. Ask user for mode (Encrypt vs Decrypt)
    let mode = tui::ask_processing_mode()?;

    // 3. Find eligible files
    let eligible_files = file::find_eligible_files(mode)?;
    if eligible_files.is_empty() {
        println!("No eligible files found for {:?} operation", mode);
        return Ok(());
    }

    // 4. Select file
    let input_path = tui::choose_file(&eligible_files)?;

    // 5. Determine output path
    let output_path = file::get_output_path(&input_path, mode);

    // 6. Validate input
    file::validate_path(&input_path, true)?;

    // 7. Check overwrite
    if file::validate_path(&output_path, false).is_err() {
        let clean_path = output_path
            .strip_prefix(".")
            .unwrap_or(&output_path)
            .display();
        let overwrite =
            tui::ask_confirm(&format!("Output file {} exists. Overwrite?", clean_path))?;
        if !overwrite {
            return Err(anyhow!("operation canceled by user"));
        }
    }

    // 8. Ask password
    let password = if mode == ProcessorMode::Encrypt {
        let p1 = tui::ask_password("Enter password:")?;
        let p2 = tui::ask_password("Confirm password:")?;
        if p1 != p2 {
            anyhow::bail!("passwords do not match");
        }
        p1
    } else {
        tui::ask_password("Enter password:")?
    };

    // 9. Show info
    tui::show_processing_info(mode, input_path.to_str().unwrap_or("?"));

    // 10. Process
    match mode {
        ProcessorMode::Encrypt => {
            processor::encrypt_file(&input_path, &output_path, &password)?;
        }
        ProcessorMode::Decrypt => {
            processor::decrypt_file(&input_path, &output_path, &password)?;
        }
    }

    tui::show_success_info(mode, output_path.to_str().unwrap_or("?"));

    // 12. Delete original
    let file_type = match mode {
        ProcessorMode::Encrypt => "original",
        ProcessorMode::Decrypt => "encrypted",
    };
    let clean_path = input_path
        .strip_prefix(".")
        .unwrap_or(&input_path)
        .display();
    if tui::ask_confirm(&format!("Delete {} file {}?", file_type, clean_path))? {
        file::remove_file(&input_path)?;
        tui::show_source_deleted(input_path.to_str().unwrap_or("?"));
    }

    Ok(())
}
