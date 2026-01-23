use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::Processor;
use crate::types::{Processing, ProcessorMode};
use crate::ui::prompt::Prompt;
use crate::ui::{self};

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
}

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
            Some(Commands::Encrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Encryption, &prompt),
            Some(Commands::Decrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Decryption, &prompt),
            Some(Commands::Interactive) | None => Self::run_interactive(&prompt),
        }
    }

    fn run_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
        let mut input = File::new(input_path);
        let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));
        let password = password.map(Ok).unwrap_or_else(|| Self::get_password(prompt, processing))?;

        Self::process(processing, &mut input, &output, &password)?;
        ui::show_success(processing.mode(), output.path());

        Ok(())
    }

    fn run_interactive(prompt: &Prompt) -> Result<()> {
        ui::clear_screen()?;
        ui::print_banner()?;

        let mode = prompt.select_processing_mode()?;
        let processing = match mode {
            ProcessorMode::Encrypt => Processing::Encryption,
            ProcessorMode::Decrypt => Processing::Decryption,
        };

        let mut files = File::discover(mode);
        ensure!(!files.is_empty(), "no eligible files found");

        ui::show_file_info(&mut files)?;

        let path = prompt.select_file(&files)?;
        let mut input = File::new(path.to_string_lossy().into_owned());
        input.validate(true)?;

        let output = File::new(input.output_path(mode).to_string_lossy().into_owned());

        if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
            bail!("operation canceled");
        }

        let password = Self::get_password(prompt, processing)?;

        Self::process(processing, &mut input, &output, &password)?;

        ui::show_success(mode, output.path());

        let label = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };
        if prompt.confirm_file_deletion(input.path(), label)? {
            input.delete()?;
            ui::show_source_deleted(input.path());
        }

        Ok(())
    }

    fn process(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
        let processor = Processor::new(password);

        match processing {
            Processing::Encryption => processor.encrypt(input, output),
            Processing::Decryption => processor.decrypt(input, output),
        }
        .with_context(|| format!("{} failed: {}", processing, input.path().display()))
    }

    fn get_password(prompt: &Prompt, processing: Processing) -> Result<String> {
        match processing {
            Processing::Encryption => prompt.prompt_encryption_password(),
            Processing::Decryption => prompt.prompt_decryption_password(),
        }
    }
}
