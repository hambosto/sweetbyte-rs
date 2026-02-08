use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::Processor;
use crate::types::{Password, Processing, ProcessorMode};
use crate::ui::prompt::Prompt;

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
pub struct App {
    #[command(subcommand)]
    command: Option<Commands>,
}

impl App {
    pub fn init() -> Result<Self> {
        let subscriber = tracing_subscriber::fmt().with_file(true).with_line_number(true).finish();
        tracing::subscriber::set_global_default(subscriber)?;
        Ok(Self::parse())
    }

    pub async fn execute(self) -> Result<()> {
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);
        match self.command {
            Some(Commands::Encrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Encryption, &prompt).await,
            Some(Commands::Decrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Decryption, &prompt).await,
            Some(Commands::Interactive) | None => Self::run_interactive(&prompt).await,
        }
    }

    async fn run_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
        let input = File::new(&input_path);
        let output = File::new(output_path.map(std::path::PathBuf::from).unwrap_or_else(|| input.output_path(processing.mode())));
        let password: Password = match password.map(Password::from_string) {
            Some(password) => password,
            None => Self::get_password(prompt, processing)?,
        };

        Self::process(processing, &input, &output, password).await?;

        crate::ui::show_success(processing.mode(), output.path());

        Ok(())
    }

    async fn run_interactive(prompt: &Prompt) -> Result<()> {
        crate::ui::clear_screen()?;
        crate::ui::print_banner()?;

        let mode = Prompt::select_processing_mode()?;
        let processing = match mode {
            ProcessorMode::Encrypt => Processing::Encryption,
            ProcessorMode::Decrypt => Processing::Decryption,
        };

        let mut files = File::discover(mode);
        if files.is_empty() {
            anyhow::bail!("no eligible files found");
        }

        crate::ui::show_file_info(&mut files).await?;

        let path = Prompt::select_file(&files)?;

        let mut input = File::new(&path);

        if !input.validate().await {
            anyhow::bail!("invalid input file: {}", path.display());
        }

        let output = File::new(input.output_path(mode));
        if output.exists() && !Prompt::confirm_file_overwrite(output.path())? {
            anyhow::bail!("operation canceled");
        }

        let password = Self::get_password(prompt, processing)?;

        Self::process(processing, &input, &output, password).await?;

        crate::ui::show_success(mode, output.path());

        let label = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };

        if Prompt::confirm_file_deletion(input.path(), label)? {
            input.delete().await?;
            crate::ui::show_source_deleted(input.path());
        }

        Ok(())
    }

    async fn process(processing: Processing, input: &File, output: &File, password: Password) -> Result<()> {
        let processor = Processor::new(password);

        let result = match processing {
            Processing::Encryption => processor.encrypt(input, output).await,
            Processing::Decryption => processor.decrypt(input, output).await,
        };

        result.with_context(|| format!("{} failed: {}", processing, input.path().display()))
    }

    fn get_password(prompt: &Prompt, processing: Processing) -> Result<Password> {
        match processing {
            Processing::Encryption => Ok(Password::new(&prompt.prompt_encryption_password()?)),
            Processing::Decryption => Ok(Password::new(&prompt.prompt_decryption_password()?)),
        }
    }
}
