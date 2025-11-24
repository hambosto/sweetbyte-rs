use crate::file;
use crate::processor::Processor;
use crate::tui;
use crate::types::ProcessorMode;
use anyhow::{anyhow, Result};
use std::path::Path;

pub struct Workflow {
    processor: Processor,
}

impl Default for Workflow {
    fn default() -> Self {
        Self::new()
    }
}

impl Workflow {
    pub fn new() -> Self {
        let processor = Processor::new();
        Self { processor }
    }

    pub fn run(&self) -> Result<()> {
        // Clear screen and print banner (Go does this)
        // tui::clear_screen()?; // Assuming we had this, but we don't. Skipping clear for now.
        tui::print_banner();

        self.run_interactive_loop()
    }

    fn run_interactive_loop(&self) -> Result<()> {
        // 1. Get Processing Mode
        let mode = tui::ask_processing_mode()?;

        // 2. Find Eligible Files
        let eligible_files = file::find_eligible_files(mode)?;
        if eligible_files.is_empty() {
            println!("No eligible files found for {:?} operation", mode);
            return Ok(());
        }

        // 5. Choose File
        let selected_file = tui::choose_file(&eligible_files)?;

        // 6. Show Processing Info
        tui::show_processing_info(mode, selected_file.to_str().unwrap_or("<invalid>"));

        // 7. Process File
        self.process_file(&selected_file, mode)
    }

    fn process_file(&self, input_path: &Path, mode: ProcessorMode) -> Result<()> {
        use crate::header::{self, Header};
        use std::fs::File;

        let output_path = file::get_output_path(input_path, mode);

        // Validate paths
        file::validate_path(input_path, true)?;

        // Check output overwrite
        if file::validate_path(&output_path, false).is_err()
            && !tui::ask_confirm(&format!(
                "Output file '{}' exists. Overwrite?",
                output_path.display()
            ))?
        {
            return Err(anyhow!("operation canceled by user"));
        }

        // Get Password
        let password = tui::ask_password("Enter password:")?;
        if mode == ProcessorMode::Encrypt {
            let confirm = tui::ask_password("Confirm password:")?;
            if password != confirm {
                return Err(anyhow!("passwords do not match"));
            }
        }

        // Get appropriate file size for progress bar
        let progress_size = match mode {
            ProcessorMode::Encrypt => {
                // For encryption: use input file size
                std::fs::metadata(input_path).map(|m| m.len()).unwrap_or(0)
            }
            ProcessorMode::Decrypt => {
                // For decryption: read header to get original (decrypted) size
                let mut file = File::open(input_path)?;
                let mut header = Header::new()?;
                header::marshal::unmarshal(&mut header, &mut file)?;
                header.get_original_size()? as u64
            }
        };

        let pb = tui::Progress::new(progress_size);

        let result = match mode {
            ProcessorMode::Encrypt => {
                self.processor
                    .encrypt(input_path, &output_path, &password, {
                        let pb = pb.clone();
                        Some(std::sync::Arc::new(move |bytes| pb.inc(bytes)))
                    })
            }
            ProcessorMode::Decrypt => {
                self.processor
                    .decrypt(input_path, &output_path, &password, {
                        let pb = pb.clone();
                        Some(std::sync::Arc::new(move |bytes| pb.inc(bytes)))
                    })
            }
        };

        pb.finish_with_message("Done");

        match result {
            Ok(_) => {
                tui::show_success_info(mode, output_path.to_str().unwrap_or("<invalid>"));

                // Confirm Removal
                let file_type = match mode {
                    ProcessorMode::Encrypt => "original",
                    ProcessorMode::Decrypt => "encrypted",
                };

                if tui::ask_confirm(&format!(
                    "Delete {} file '{}'?",
                    file_type,
                    input_path.display()
                ))? {
                    file::remove_file(input_path)?;
                    tui::show_source_deleted(input_path.to_str().unwrap_or("<invalid>"));
                }
            }
            Err(e) => {
                tui::print_error(&format!(
                    "Failed to process {}: {}",
                    input_path.display(),
                    e
                ));
                return Err(e);
            }
        }

        Ok(())
    }
}
