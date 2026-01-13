//! CLI commands and argument parsing.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::file::operations::get_output_path;
use crate::processor;
use crate::types::ProcessorMode;
use crate::ui::prompt::{get_decryption_password, get_encryption_password};

/// SweetByte - Multi-layered file encryption with error correction.
#[derive(Parser)]
#[command(name = "sweetbyte")]
#[command(version = "1.0")]
#[command(
    about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction. Run without arguments for interactive mode."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands.
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

/// Parses CLI arguments.
pub fn parse() -> Cli {
    Cli::parse()
}

/// Runs a CLI command.
///
/// # Arguments
/// * `cmd` - The command to run
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

        Commands::Interactive => crate::interactive::run(),
    }
}

fn encrypt_file(
    input: &std::path::Path,
    output: Option<PathBuf>,
    password: Option<String>,
) -> Result<()> {
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

fn decrypt_file(
    input: &std::path::Path,
    output: Option<PathBuf>,
    password: Option<String>,
) -> Result<()> {
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
