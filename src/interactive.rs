//! Interactive mode for SweetByte.

use anyhow::{Context, Result, bail};

use crate::file::discovery::find_eligible_files;
use crate::file::operations::get_output_path;
use crate::processor;
use crate::types::ProcessorMode;
use crate::ui::display::{print_banner, show_file_info, show_success};
use crate::ui::prompt::{
    choose_file, confirm_removal, get_decryption_password, get_encryption_password,
    get_processing_mode,
};

/// Runs the interactive mode.
pub fn run() -> Result<()> {
    print_banner();

    let mode = get_processing_mode()?;

    let files = find_eligible_files(mode)?;

    if files.is_empty() {
        bail!("No eligible files found for {}", mode);
    }

    let file_infos: Vec<_> = files
        .iter()
        .map(|p| crate::types::FileInfo {
            path: p.clone(),
            size: std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
            is_encrypted: crate::file::operations::is_encrypted_file(p),
        })
        .collect();

    show_file_info(&file_infos)?;

    let selected = choose_file(&files)?;
    let output = get_output_path(&selected, mode);

    match mode {
        ProcessorMode::Encrypt => {
            let password = get_encryption_password()?;

            processor::encrypt(&selected, &output, &password)
                .with_context(|| format!("encryption failed for {}", selected.display()))?;

            show_success(mode, &output);

            if confirm_removal(&selected, "original")? {
                std::fs::remove_file(&selected)
                    .with_context(|| format!("failed to remove {}", selected.display()))?;
                crate::ui::display::show_source_deleted(&selected);
            }
        }
        ProcessorMode::Decrypt => {
            let password = get_decryption_password()?;

            processor::decrypt(&selected, &output, &password)
                .with_context(|| format!("decryption failed for {}", selected.display()))?;

            show_success(mode, &output);

            if confirm_removal(&selected, "encrypted")? {
                std::fs::remove_file(&selected)
                    .with_context(|| format!("failed to remove {}", selected.display()))?;
                crate::ui::display::show_source_deleted(&selected);
            }
        }
    }

    Ok(())
}
