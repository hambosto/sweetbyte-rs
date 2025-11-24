use crate::file;
use crate::processor::Processor;
use crate::tui;
use crate::types::ProcessorMode;
use anyhow::Result;
use std::path::Path;

pub fn handle_encrypt(
    input: &str,
    output: Option<String>,
    password: Option<String>,
    delete: bool,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => {
            let p = tui::ask_password("Enter password:")?;
            let confirm = tui::ask_password("Confirm password:")?;
            if p != confirm {
                tui::print_error("Passwords do not match");
                return Ok(());
            }
            p
        }
    };

    let processor = Processor::new();

    let file_path = Path::new(input);
    let dest = output
        .map(|s| s.into())
        .unwrap_or_else(|| file::get_output_path(file_path, ProcessorMode::Encrypt));

    println!("Encrypting {} -> {}", file_path.display(), dest.display());

    let file_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    let pb = tui::Progress::new(file_size);

    let result = processor.encrypt(file_path, &dest, &password, {
        let pb = pb.clone();
        Some(std::sync::Arc::new(move |bytes| {
            pb.inc(bytes);
        }))
    });

    match result {
        Ok(_) => {
            pb.finish_with_message("Done");
            tui::print_success(&format!("File encrypted successfully: {}", dest.display()));

            let should_delete = if delete {
                true
            } else {
                tui::ask_confirm(&format!("Delete original file {}?", file_path.display()))
                    .unwrap_or(false)
            };

            if should_delete {
                println!("Deleting source file: {}", file_path.display());
                if let Err(e) = file::remove_file(file_path) {
                    tui::print_error(&format!("Failed to delete source: {}", e));
                } else {
                    tui::print_success("Source file deleted successfully");
                }
            }
        }
        Err(e) => {
            pb.finish_with_message(&format!("Failed: {}", e));
            tui::print_error(&format!("Failed: {}", e));
        }
    }

    Ok(())
}

pub fn handle_decrypt(
    input: &str,
    output: Option<String>,
    password: Option<String>,
    delete: bool,
) -> Result<()> {
    use crate::header::{self, Header};
    use std::fs::File;

    let password = match password {
        Some(p) => p,
        None => tui::ask_password("Enter password:")?,
    };

    let processor = Processor::new();

    let file_path = Path::new(input);
    let dest = output
        .map(|s| s.into())
        .unwrap_or_else(|| file::get_output_path(file_path, ProcessorMode::Decrypt));

    println!("Decrypting {} -> {}", file_path.display(), dest.display());

    // Read header to get original file size for accurate progress
    let original_size = {
        let mut file = File::open(file_path)?;
        let mut header = Header::new()?;
        header::marshal::unmarshal(&mut header, &mut file)?;
        header.get_original_size()? as u64
    };

    // Use original (decrypted) size for progress bar, not encrypted size
    let pb = tui::Progress::new(original_size);

    let result = processor.decrypt(file_path, &dest, &password, {
        let pb = pb.clone();
        Some(std::sync::Arc::new(move |bytes| {
            pb.inc(bytes);
        }))
    });

    match result {
        Ok(_) => {
            pb.finish_with_message("Done");
            tui::print_success(&format!("File decrypted successfully: {}", dest.display()));

            let should_delete = if delete {
                true
            } else {
                tui::ask_confirm(&format!("Delete original file {}?", file_path.display()))
                    .unwrap_or(false)
            };

            if should_delete {
                println!("Deleting source file: {}", file_path.display());
                if let Err(e) = file::remove_file(file_path) {
                    tui::print_error(&format!("Failed to delete source: {}", e));
                } else {
                    tui::print_success("Source file deleted successfully");
                }
            }
        }
        Err(e) => {
            pb.finish_with_message(&format!("Failed: {}", e));
            tui::print_error(&format!("Failed: {}", e));
        }
    }

    Ok(())
}
