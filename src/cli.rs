use anyhow::{Context, Result, bail, ensure};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::{Decryptor, Encryptor};
use crate::types::{Processing, ProcessorMode};
use crate::ui::display::*;
use crate::ui::prompt::Prompt;

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    pub fn init() -> Self {
        Self::parse()
    }

    pub fn execute(self) -> Result<()> {
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);

        match self.command {
            Some(cmd) => cmd.run(&prompt),
            None => run_interactive(&prompt),
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
    },

    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
    },

    Interactive,

    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    pub fn run(self, prompt: &Prompt) -> Result<()> {
        match self {
            Self::Encrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Encryption, prompt),
            Self::Decrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Decryption, prompt),
            Self::Interactive => run_interactive(prompt),
            Self::Completions { shell } => generate_completions(shell),
        }
    }
}

fn run_cli_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
    let mut input = File::new(input_path);
    let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));
    let password = match password {
        Some(pwd) => pwd,
        None => prompt_password(prompt, processing)?,
    };

    process_file(processing, &mut input, &output, &password)?;
    println!("✓ {}: {} -> {}", processing, input.path().display(), output.path().display());

    Ok(())
}

fn run_interactive(prompt: &Prompt) -> Result<()> {
    clear_screen()?;
    print_banner()?;

    let mode = prompt.select_processing_mode()?;
    let input = select_file(prompt, mode)?;
    let processing = match mode {
        ProcessorMode::Encrypt => Processing::Encryption,
        ProcessorMode::Decrypt => Processing::Decryption,
    };

    let mut input_file = File::new(input.path().to_string_lossy().into_owned());
    input_file.validate(true)?;

    let output = File::new(input_file.output_path(processing.mode()).to_string_lossy().into_owned());
    if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
        bail!("operation canceled");
    }

    let password = prompt_password(prompt, processing)?;
    process_file(processing, &mut input_file, &output, &password)?;

    show_success(mode, output.path());
    delete_source(prompt, &input_file, processing.mode())?;

    Ok(())
}

fn process_file(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
    match processing {
        Processing::Encryption => Encryptor::new(password).encrypt(input, output),
        Processing::Decryption => Decryptor::new(password).decrypt(input, output),
    }
    .with_context(|| format!("{} failed: {}", processing, input.path().display()))
}

fn prompt_password(prompt: &Prompt, processing: Processing) -> Result<String> {
    match processing {
        Processing::Encryption => prompt.prompt_encryption_password(),
        Processing::Decryption => prompt.prompt_decryption_password(),
    }
}

fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<File> {
    let mut files = File::discover(mode)?;
    ensure!(!files.is_empty(), "no eligible files found");

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
