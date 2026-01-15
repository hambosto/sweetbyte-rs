use std::fs::remove_file;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::file::discovery::find_eligible_files;
use crate::file::operations::{get_file_info_list, get_output_path};
use crate::file::validation::validate_path;
use crate::processor::{decrypt, encrypt};
use crate::types::ProcessorMode;
use crate::ui::display::{clear_screen, print_banner, show_file_info, show_source_deleted, show_success};
use crate::ui::prompt::{choose_file, confirm_overwrite, confirm_removal, get_decryption_password, get_encryption_password, get_processing_mode};

#[derive(Parser)]
#[command(name = "sweetbyte-rs")]
#[command(version = "1.0")]
#[command(about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction. Run without arguments for interactive mode.")]
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
        Commands::Encrypt { input, output, password } => encrypt_file(&input, output, password),
        Commands::Decrypt { input, output, password } => decrypt_file(&input, output, password),
        Commands::Interactive => run_interactive(),
    }
}

fn encrypt_file(input: &Path, output: Option<PathBuf>, password: Option<String>) -> Result<()> {
    let output = output.unwrap_or_else(|| get_output_path(input, ProcessorMode::Encrypt));
    let password = match password {
        Some(p) => p,
        None => get_encryption_password()?,
    };

    encrypt(input, &output, &password).with_context(|| format!("encryption failed for {}", input.display()))?;
    println!("✓ Encrypted: {} -> {}", input.display(), output.display());

    Ok(())
}

fn decrypt_file(input: &Path, output: Option<PathBuf>, password: Option<String>) -> Result<()> {
    let output = output.unwrap_or_else(|| get_output_path(input, ProcessorMode::Decrypt));
    let password = match password {
        Some(p) => p,
        None => get_decryption_password()?,
    };

    decrypt(input, &output, &password).with_context(|| format!("decryption failed for {}", input.display()))?;
    println!("✓ Decrypted: {} -> {}", input.display(), output.display());

    Ok(())
}

pub fn run_interactive() -> Result<()> {
    clear_screen()?;
    print_banner();

    let mode = get_processing_mode()?;

    // Find eligible files
    let eligible_files = find_eligible_files(mode)?;
    if eligible_files.is_empty() {
        bail!("no eligible files found for {} operation", mode);
    }

    // Get file info list
    let file_infos = get_file_info_list(&eligible_files)?;

    // Display file info
    show_file_info(&file_infos)?;

    // Choose file
    let selected_file = choose_file(&eligible_files)?;
    let output_path = get_output_path(&selected_file, mode);

    // Validate source path
    validate_path(&selected_file, true).with_context(|| format!("source validation failed: {}", selected_file.display()))?;

    // Validate output path - if exists, ask for overwrite confirmation
    if validate_path(&output_path, false).is_err() {
        if !confirm_overwrite(&output_path)? {
            bail!("operation canceled by user");
        }
    }

    // Process file
    match mode {
        ProcessorMode::Encrypt => {
            let password = get_encryption_password()?;
            encrypt(&selected_file, &output_path, &password).with_context(|| format!("failed to encrypt {}", selected_file.display()))?;
        }
        ProcessorMode::Decrypt => {
            let password = get_decryption_password()?;
            decrypt(&selected_file, &output_path, &password).with_context(|| format!("failed to decrypt {}", selected_file.display()))?;
        }
    }

    // Show success
    show_success(mode, &output_path);

    // Confirm removal
    let file_type = match mode {
        ProcessorMode::Encrypt => "original",
        ProcessorMode::Decrypt => "encrypted",
    };

    if confirm_removal(&selected_file, file_type)? {
        remove_file(&selected_file).with_context(|| format!("failed to delete source file: {}", selected_file.display()))?;
        show_source_deleted(&selected_file);
    }

    Ok(())
}
