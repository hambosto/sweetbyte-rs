use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::file::File;
use crate::processor::{Decryptor, Encryptor};
use crate::types::{Processing, ProcessorMode};
use crate::ui::display::*;
use crate::ui::prompt::Prompt;

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    pub fn init() -> Self {
        Self::parse()
    }

    pub fn execute(self) -> Result<()> {
        match self.command {
            Some(cmd) => cmd.run(),
            None => run_interactive(),
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file using authenticated encryption.
    ///
    /// - Uses AES-256-GCM and XChaCha20-Poly1305.
    /// - Prompts for password if not provided.
    /// - Output defaults to an auto-derived path.
    Encrypt {
        /// Path to the input file to encrypt.
        #[arg(short, long)]
        input: String,

        /// Optional output file path.
        #[arg(short, long)]
        output: Option<String>,

        /// Optional encryption password (will prompt if omitted).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a previously encrypted file.
    ///
    /// - Performs integrity verification.
    /// - Applies Reed-Solomon error correction.
    /// - Prompts for password if not provided.
    Decrypt {
        /// Path to the encrypted input file.
        #[arg(short, long)]
        input: String,

        /// Optional output file path.
        #[arg(short, long)]
        output: Option<String>,

        /// Optional decryption password (will prompt if omitted).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Launch interactive TUI mode.
    Interactive,

    /// Generate shell completion scripts.
    ///
    /// Example:
    ///   sweetbyte-rs completions bash > /etc/bash_completion.d/sweetbyte-rs
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Encrypt { input, output, password } => run_cli(input, output, password, Processing::Encryption),
            Self::Decrypt { input, output, password } => run_cli(input, output, password, Processing::Decryption),
            Self::Interactive => run_interactive(),
            Self::Completions { shell } => generate_completions(shell),
        }
    }
}

fn run_cli(input: String, output: Option<String>, password: Option<String>, processing: Processing) -> Result<()> {
    let mut input = File::new(input);
    let output = File::new(output.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));
    let password = password.unwrap_or_else(|| prompt_password(processing).unwrap());

    process_file(processing, &mut input, &output, &password)?;
    println!("✓ {}: {} -> {}", processing, input.path().display(), output.path().display());
    Ok(())
}

fn run_interactive() -> Result<()> {
    clear_screen()?;
    print_banner()?;

    let prompt = Prompt::new();
    let mode = prompt.select_processing_mode()?;

    let mut input = select_file(&prompt, mode)?;
    let output = File::new(input.output_path(mode));

    input.validate(true)?;
    if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
        bail!("operation canceled");
    }

    let processing = match mode {
        ProcessorMode::Encrypt => Processing::Encryption,
        ProcessorMode::Decrypt => Processing::Decryption,
    };

    let password = prompt_password(processing)?;

    process_file(processing, &mut input, &output, &password)?;

    show_success(mode, output.path());
    delete_source(&prompt, &input, mode)?;
    Ok(())
}

fn process_file(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
    match processing {
        Processing::Encryption => Encryptor::new(password).encrypt(input, output),
        Processing::Decryption => Decryptor::new(password).decrypt(input, output),
    }
    .with_context(|| format!("{} failed: {}", processing, input.path().display()))
}

fn prompt_password(processing: Processing) -> Result<String> {
    let prompt = Prompt::new();
    match processing {
        Processing::Encryption => prompt.prompt_encryption_password(),
        Processing::Decryption => prompt.prompt_decryption_password(),
    }
}

fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<File> {
    let mut files = File::discover(mode)?;
    if files.is_empty() {
        bail!("no eligible files found");
    }

    show_file_info(&mut files)?;
    let path = prompt.select_file(&files)?;
    Ok(File::new(path.to_string_lossy().into_owned()))
}

fn delete_source(prompt: &Prompt, file: &File, mode: ProcessorMode) -> Result<()> {
    let label = if mode == ProcessorMode::Encrypt { "original" } else { "encrypted" };

    if prompt.confirm_file_deletion(file.path(), label)? {
        file.delete()?;
        show_source_deleted(file.path());
    }
    Ok(())
}

fn generate_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sweetbyte-rs", &mut std::io::stdout());
    Ok(())
}
