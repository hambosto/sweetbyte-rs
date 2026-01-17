use std::fs::remove_file;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::file::discovery::find_eligible_files;
use crate::file::operations::{get_file_info_list, get_output_path};
use crate::file::validation::validate_path;
use crate::processor::{Decryptor, Encryptor};
use crate::types::ProcessorMode;
use crate::ui::display::{clear_screen, print_banner, show_file_info, show_source_deleted, show_success};
use crate::ui::prompt::Prompt;

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction. Run without arguments for interactive mode.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

impl Cli {
    #[inline]
    pub fn init() -> Self {
        Self::parse()
    }

    pub fn execute(self) -> Result<()> {
        match self.command {
            Some(cmd) => cmd.run(),
            None => Interactive::run(),
        }
    }
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

impl Commands {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Encrypt { input, output, password } => process_file(&input, output, password, ProcessorMode::Encrypt),
            Self::Decrypt { input, output, password } => process_file(&input, output, password, ProcessorMode::Decrypt),
            Self::Interactive => Interactive::run(),
        }
    }
}

fn process_file(input: &Path, output: Option<PathBuf>, password: Option<String>, mode: ProcessorMode) -> Result<()> {
    let output = output.unwrap_or_else(|| get_output_path(input, mode));

    let password = password.map_or_else(
        || match mode {
            ProcessorMode::Encrypt => Prompt::new().prompt_encryption_password(),
            ProcessorMode::Decrypt => Prompt::new().prompt_decryption_password(),
        },
        Ok,
    )?;

    let action = match mode {
        ProcessorMode::Encrypt => {
            Encryptor::new(&password).encrypt(input, &output)?;
            "Encrypted"
        }
        ProcessorMode::Decrypt => {
            Decryptor::new(&password).decrypt(input, &output)?;
            "Decrypted"
        }
    };

    println!("✓ {action}: {} -> {}", input.display(), output.display());
    Ok(())
}

#[allow(non_snake_case)]
mod Interactive {
    use super::*;

    pub fn run() -> Result<()> {
        clear_screen()?;
        print_banner()?;

        let prompt = Prompt::new();

        let mode = prompt.select_processing_mode()?;
        let selected_file = select_file(&prompt, mode)?;
        let output_path = get_output_path(&selected_file, mode);

        validate_source(&selected_file)?;
        validate_output(&prompt, &output_path)?;

        let password = get_password(&prompt, mode)?;
        execute_operation(mode, &selected_file, &output_path, &password)?;

        show_success(mode, &output_path);
        cleanup_source(&prompt, &selected_file, mode)?;

        Ok(())
    }

    fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<PathBuf> {
        let eligible_files = find_eligible_files(mode)?;

        if eligible_files.is_empty() {
            bail!("no eligible files found for {mode} operation");
        }

        let file_infos = get_file_info_list(&eligible_files)?;
        show_file_info(&file_infos)?;

        prompt.select_file(&eligible_files)
    }

    fn validate_source(path: &Path) -> Result<()> {
        validate_path(path, true).with_context(|| format!("source validation failed: {}", path.display()))
    }

    fn validate_output(prompt: &Prompt, path: &Path) -> Result<()> {
        if validate_path(path, false).is_err() && !prompt.confirm_file_overwrite(path)? {
            bail!("operation canceled by user");
        }
        Ok(())
    }

    fn get_password(prompt: &Prompt, mode: ProcessorMode) -> Result<String> {
        match mode {
            ProcessorMode::Encrypt => prompt.prompt_encryption_password(),
            ProcessorMode::Decrypt => prompt.prompt_decryption_password(),
        }
    }

    fn execute_operation(mode: ProcessorMode, input: &Path, output: &Path, password: &str) -> Result<()> {
        match mode {
            ProcessorMode::Encrypt => Encryptor::new(password).encrypt(input, output).with_context(|| format!("failed to encrypt {}", input.display())),
            ProcessorMode::Decrypt => Decryptor::new(password).decrypt(input, output).with_context(|| format!("failed to decrypt {}", input.display())),
        }
    }

    fn cleanup_source(prompt: &Prompt, path: &Path, mode: ProcessorMode) -> Result<()> {
        let file_type = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };

        if prompt.confirm_file_deletion(path, file_type)? {
            remove_file(path).with_context(|| format!("failed to delete source file: {}", path.display()))?;
            show_source_deleted(path);
        }

        Ok(())
    }
}
