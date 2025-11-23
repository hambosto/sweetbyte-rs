use crate::file_manager::FileManager;
use crate::processor::Processor;
use crate::tui;
use crate::types::ProcessorMode;
use anyhow::Result;

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

    let file_manager = FileManager::new();
    let processor = Processor::new(FileManager::new());

    // Check if input is a file or directory
    // Go CLI seems to handle single file input primarily based on the code snippet:
    // "if _, err := os.Stat(inputFile); ..."
    // But FindEligibleFiles is used in interactive.
    // The Rust CLI was using find_eligible_files which implies directory support.
    // However, the Go CLI `runEncrypt` takes a single `inputFile`.
    // To strictly align with Go CLI `runEncrypt`, we should process a single file.
    // But `find_eligible_files` is useful.
    // Let's stick to the Rust CLI behavior of supporting directories if that was the intent,
    // OR strictly align with Go which seems to target single file in CLI.
    // The Go CLI `runEncrypt` does NOT call `FindEligibleFiles`. It processes `inputFile`.
    // So if `inputFile` is a directory, `os.Open` might succeed but `processor.Encrypt` expects a file.
    // Let's align with Go CLI: Process the specific input file.

    // Actually, looking at Go's `runEncrypt`:
    // if _, err := os.Stat(inputFile); ...
    // processor.Encrypt(inputFile, ...)
    // It processes a single file.

    // So we should NOT use find_eligible_files here if we want strict alignment.
    // We should process `input` directly.

    let file_path = input;
    let dest = output
        .clone()
        .unwrap_or_else(|| file_manager.get_output_path(file_path, ProcessorMode::Encrypt));

    println!("Encrypting {} -> {}", file_path, dest);

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
            tui::print_success(&format!("File encrypted successfully: {}", dest));

            let should_delete = if delete {
                true
            } else {
                tui::ask_confirm(&format!("Delete original file '{}'?", file_path)).unwrap_or(false)
            };

            if should_delete {
                println!("Deleting source file: {}", file_path);
                if let Err(e) = file_manager.remove(file_path) {
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
    use crate::header::Header;
    use std::fs::File;

    let password = match password {
        Some(p) => p,
        None => tui::ask_password("Enter password:")?,
    };

    let file_manager = FileManager::new();
    let processor = Processor::new(FileManager::new());

    let file_path = input;
    let dest = output
        .clone()
        .unwrap_or_else(|| file_manager.get_output_path(file_path, ProcessorMode::Decrypt));

    println!("Decrypting {} -> {}", file_path, dest);

    // Read header to get original file size for accurate progress
    let original_size = {
        let mut file = File::open(file_path)?;
        let mut header = Header::new()?;
        header.unmarshal(&mut file)?;
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
            tui::print_success(&format!("File decrypted successfully: {}", dest));

            let should_delete = if delete {
                true
            } else {
                tui::ask_confirm(&format!("Delete original file '{}'?", file_path)).unwrap_or(false)
            };

            if should_delete {
                println!("Deleting source file: {}", file_path);
                if let Err(e) = file_manager.remove(file_path) {
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
