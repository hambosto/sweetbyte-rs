use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::file::File;
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
        input: String,

        /// Output file path (optional).
        #[arg(short, long)]
        output: Option<String>,

        /// Password for encryption (optional, will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a file with error correction.
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        input: String,

        /// Output file path (optional).
        #[arg(short, long)]
        output: Option<String>,

        /// Password for decryption (optional, will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Start interactive mode.
    Interactive,

    /// Generate shell completions.
    Completions {
        /// Shell type to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Encrypt { input, output, password } => process_file(input, output, password, ProcessorMode::Encrypt),
            Self::Decrypt { input, output, password } => process_file(input, output, password, ProcessorMode::Decrypt),
            Self::Interactive => Interactive::run(),
            Self::Completions { shell } => {
                let mut cmd = Cli::command();
                clap_complete::generate(shell, &mut cmd, "sweetbyte-rs", &mut std::io::stdout());
                Ok(())
            }
        }
    }
}

fn process_file(input: String, output: Option<String>, password: Option<String>, mode: ProcessorMode) -> Result<()> {
    let mut input_file = File::new(input);

    let output_file = match output {
        Some(path) => File::new(path),
        None => File::new(input_file.output_path(mode)),
    };

    let password = password.map_or_else(
        || match mode {
            ProcessorMode::Encrypt => Prompt::new().prompt_encryption_password(),
            ProcessorMode::Decrypt => Prompt::new().prompt_decryption_password(),
        },
        Ok,
    )?;

    let action = match mode {
        ProcessorMode::Encrypt => {
            Encryptor::new(&password).encrypt(&mut input_file, &output_file)?;
            "Encrypted"
        }
        ProcessorMode::Decrypt => {
            Decryptor::new(&password).decrypt(&input_file, &output_file)?;
            "Decrypted"
        }
    };

    println!("✓ {action}: {} -> {}", input_file.path().display(), output_file.path().display());
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
        let mut selected_file = select_file(&prompt, mode)?;
        let output_file = File::new(selected_file.output_path(mode));

        validate_source(&mut selected_file)?;
        validate_output(&prompt, &output_file)?;

        let password = get_password(&prompt, mode)?;
        execute_operation(mode, &mut selected_file, &output_file, &password)?;

        show_success(mode, output_file.path());
        cleanup_source(&prompt, &selected_file, mode)?;

        Ok(())
    }

    fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<File> {
        let mut eligible_files = File::discover(mode)?;

        if eligible_files.is_empty() {
            bail!("no eligible files found for {mode} operation");
        }

        show_file_info(&mut eligible_files)?;

        let selected_path = prompt.select_file(&eligible_files)?;
        Ok(File::new(selected_path))
    }

    fn validate_source(file: &mut File) -> Result<()> {
        file.validate(true).with_context(|| format!("source validation failed: {}", file.path().display()))
    }

    fn validate_output(prompt: &Prompt, file: &File) -> Result<()> {
        if file.exists() && !prompt.confirm_file_overwrite(file.path())? {
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

    fn execute_operation(mode: ProcessorMode, input: &mut File, output: &File, password: &str) -> Result<()> {
        match mode {
            ProcessorMode::Encrypt => Encryptor::new(password).encrypt(input, output).with_context(|| format!("failed to encrypt {}", input.path().display())),
            ProcessorMode::Decrypt => Decryptor::new(password).decrypt(input, output).with_context(|| format!("failed to decrypt {}", input.path().display())),
        }
    }

    fn cleanup_source(prompt: &Prompt, file: &File, mode: ProcessorMode) -> Result<()> {
        let file_type = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };

        if prompt.confirm_file_deletion(file.path(), file_type)? {
            file.delete().with_context(|| format!("failed to delete source file: {}", file.path().display()))?;
            show_source_deleted(file.path());
        }

        Ok(())
    }
}
