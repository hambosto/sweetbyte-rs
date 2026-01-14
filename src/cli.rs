use std::fs::{metadata, remove_file};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::file::discovery::find_eligible_files;
use crate::file::operations::{get_output_path, is_encrypted_file};
use crate::processor;
use crate::types::{FileInfo, ProcessorMode};
use crate::ui::display::{print_banner, show_file_info, show_source_deleted, show_success};
use crate::ui::prompt::{
    choose_file, confirm_removal, get_decryption_password, get_encryption_password,
    get_processing_mode,
};

#[derive(Parser)]
#[command(name = "sweetbyte-rs")]
#[command(version = "1.0")]
#[command(
    about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error \
             correction. Run without arguments for interactive mode."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file with multi-layered encryption.
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path (optional).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Password for encryption (optional, will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a file with error correction.
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path (optional).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Password for decryption (optional, will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Start interactive mode.
    Interactive,
}

pub fn parse() -> Cli {
    Cli::parse()
}

pub fn run_command(cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Encrypt {
            input,
            output,
            password,
        } => encrypt_file(&input, output, password),

        Commands::Decrypt {
            input,
            output,
            password,
        } => decrypt_file(&input, output, password),

        Commands::Interactive => run_interactive(),
    }
}

fn encrypt_file(input: &Path, output: Option<PathBuf>, password: Option<String>) -> Result<()> {
    let output = output.unwrap_or_else(|| get_output_path(input, ProcessorMode::Encrypt));
    let password = match password {
        Some(p) => p,
        None => get_encryption_password()?,
    };

    processor::encrypt(input, &output, &password)
        .with_context(|| format!("encryption failed for {}", input.display()))?;

    println!("✓ Encrypted: {} -> {}", input.display(), output.display());

    Ok(())
}

fn decrypt_file(input: &Path, output: Option<PathBuf>, password: Option<String>) -> Result<()> {
    let output = output.unwrap_or_else(|| get_output_path(input, ProcessorMode::Decrypt));
    let password = match password {
        Some(p) => p,
        None => get_decryption_password()?,
    };

    processor::decrypt(input, &output, &password)
        .with_context(|| format!("decryption failed for {}", input.display()))?;

    println!("✓ Decrypted: {} -> {}", input.display(), output.display());

    Ok(())
}

pub fn run_interactive() -> Result<()> {
    print_banner();

    let mode = get_processing_mode()?;
    let files = find_eligible_files(mode)?;
    if files.is_empty() {
        bail!("No eligible files found for {}", mode);
    }

    let file_infos: Vec<_> = files
        .iter()
        .map(|p| FileInfo {
            path: p.clone(),
            size: metadata(p).map(|m| m.len()).unwrap_or(0),
            is_encrypted: is_encrypted_file(p),
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
                remove_file(&selected)
                    .with_context(|| format!("failed to remove {}", selected.display()))?;
                show_source_deleted(&selected);
            }
        }
        ProcessorMode::Decrypt => {
            let password = get_decryption_password()?;

            processor::decrypt(&selected, &output, &password)
                .with_context(|| format!("decryption failed for {}", selected.display()))?;

            show_success(mode, &output);
            if confirm_removal(&selected, "encrypted")? {
                remove_file(&selected)
                    .with_context(|| format!("failed to remove {}", selected.display()))?;
                show_source_deleted(&selected);
            }
        }
    }

    Ok(())
}
