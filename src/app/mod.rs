use crate::{file, processor, tui, types::ProcessorMode};
use anyhow::{Result, anyhow};
use std::fs;

const PASSWORD_MIN_LENGTH: usize = 8;

pub fn run() -> Result<()> {
    // Initialize the prompt input handler
    let prompt = tui::PromptInput::new(PASSWORD_MIN_LENGTH);

    // 1. Show welcome banner
    tui::print_banner();

    // 2. Ask user for mode (Encrypt vs Decrypt)
    let mode = prompt.get_processing_mode()?;

    // 3. Find eligible files
    let (eligible_files, display_paths) = file::find_eligible_files_with_display(mode)?;
    if eligible_files.is_empty() {
        println!("No eligible files found for {:?} operation", mode);
        return Ok(());
    }

    // 4. Display file information in a table

    let file_sizes: Vec<u64> = eligible_files
        .iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .collect();

    let file_encrypted: Vec<bool> = eligible_files
        .iter()
        .map(|p| file::is_encrypted_file(p))
        .collect();

    tui::show_file_info(&display_paths, &file_sizes, &file_encrypted);

    // 5. Select file
    let input_path = prompt.choose_file(&eligible_files)?;

    // 6. Determine output path
    let (output_path, output_display) = file::get_output_path_with_display(&input_path, mode);

    // 7. Validate input
    file::validate_path(&input_path, true)?;

    // 8. Check overwrite
    if file::validate_path(&output_path, false).is_err() {
        let overwrite = prompt.confirm_file_overwrite(&output_display)?;
        if !overwrite {
            return Err(anyhow!("operation canceled by user"));
        }
    }

    // 9. Ask password
    let password = if mode == ProcessorMode::Encrypt {
        prompt.get_encryption_password()?
    } else {
        prompt.get_decryption_password()?
    };

    // 10. Process
    match mode {
        ProcessorMode::Encrypt => {
            processor::encrypt_file(&input_path, &output_path, &password)?;
        }
        ProcessorMode::Decrypt => {
            processor::decrypt_file(&input_path, &output_path, &password)?;
        }
    }

    tui::show_success_info(mode, &output_display);

    // 12. Delete original
    let file_type = match mode {
        ProcessorMode::Encrypt => "original",
        ProcessorMode::Decrypt => "encrypted",
    };
    let input_display = file::get_clean_path(&input_path);
    if prompt.confirm_file_removal(&input_display, file_type)? {
        file::remove_file(&input_path)?;
        tui::show_source_deleted(&input_display);
    }

    Ok(())
}
