//! Command-line interface definition and entry point logic.
//!
//! This module uses `clap` to parse command-line arguments and `dialoguer` to handle
//! interactive prompts. It routes user intent to the appropriate `Processor` actions.

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::Processor;
use crate::types::{Processing, ProcessorMode};
use crate::ui::prompt::Prompt;

/// The supported subcommands for the CLI.
#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a specific file.
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        input: String,

        /// Output file path (optional, defaults to <input>.swx).
        #[arg(short, long)]
        output: Option<String>,

        /// Password (optional, will prompt if omitted).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a specific file.
    Decrypt {
        /// Input file path (must end in .swx).
        #[arg(short, long)]
        input: String,

        /// Output file path (optional, defaults to original filename).
        #[arg(short, long)]
        output: Option<String>,

        /// Password (optional, will prompt if omitted).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Launch interactive mode (default if no args provided).
    Interactive,
}

/// The main argument parser structure.
#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    /// The command to execute.
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    /// Parses arguments from the command line.
    pub fn init() -> Self {
        Self::parse()
    }

    /// Executes the parsed command.
    ///
    /// This delegates to either `run_mode` (for direct commands) or `run_interactive`.
    pub async fn execute(self) -> Result<()> {
        // Initialize the prompt handler with config settings.
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);

        match self.command {
            Some(Commands::Encrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Encryption, &prompt).await,

            Some(Commands::Decrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Decryption, &prompt).await,

            // Default to interactive mode if no subcommand is given.
            Some(Commands::Interactive) | None => Self::run_interactive(&prompt).await,
        }
    }

    /// Runs a specific operation mode (Encrypt/Decrypt) based on CLI arguments.
    async fn run_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
        // Create file handle for input.
        let mut input = File::new(input_path);

        // Determine output path: use provided or derive from input.
        let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));

        // Get password: use provided or prompt user.
        // We use map(Ok) to fit the Option into result chaining logic.
        let password = password.map(Ok).unwrap_or_else(|| Self::get_password(prompt, processing))?;

        // Execute the processing logic.
        Self::process(processing, &mut input, &output, &password).await?;

        // Show success message.
        crate::ui::show_success(processing.mode(), output.path());

        Ok(())
    }

    /// Runs the interactive wizard.
    async fn run_interactive(prompt: &Prompt) -> Result<()> {
        // Setup UI.
        crate::ui::clear_screen()?;
        crate::ui::print_banner()?;

        // Step 1: Select Mode (Encrypt/Decrypt).
        let mode = prompt.select_processing_mode()?;
        let processing = match mode {
            ProcessorMode::Encrypt => Processing::Encryption,
            ProcessorMode::Decrypt => Processing::Decryption,
        };

        // Step 2: Discover eligible files.
        // This scans the current directory for files matching the mode criteria.
        let mut files = File::discover(mode);
        ensure!(!files.is_empty(), "no eligible files found");

        // Step 3: Show file list.
        crate::ui::show_file_info(&mut files).await?;

        // Step 4: Select file.
        let path = prompt.select_file(&files)?;
        let mut input = File::new(path.to_string_lossy().into_owned());

        // Validate selection (e.g., ensure it still exists and isn't empty).
        input.validate(true).await?;

        // Prepare output path.
        let output = File::new(input.output_path(mode).to_string_lossy().into_owned());

        // Step 5: Check overwrite.
        if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
            bail!("operation canceled");
        }

        // Step 6: Get Password.
        let password = Self::get_password(prompt, processing)?;

        // Step 7: Process.
        Self::process(processing, &mut input, &output, &password).await?;

        crate::ui::show_success(mode, output.path());

        // Step 8: Offer deletion of source file (cleanup).
        let label = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };
        if prompt.confirm_file_deletion(input.path(), label)? {
            input.delete().await?;
            crate::ui::show_source_deleted(input.path());
        }

        Ok(())
    }

    /// Helper to dispatch processing to the Processor struct.
    async fn process(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
        let processor = Processor::new(password);

        // Run the appropriate method on the processor.
        let result = match processing {
            Processing::Encryption => processor.encrypt(input, output).await,
            Processing::Decryption => processor.decrypt(input, output).await,
        };

        // Add context to any error that occurs.
        result.with_context(|| format!("{} failed: {}", processing, input.path().display()))
    }

    /// Helper to get the correct password prompt based on mode.
    fn get_password(prompt: &Prompt, processing: Processing) -> Result<String> {
        match processing {
            Processing::Encryption => prompt.prompt_encryption_password(),
            Processing::Decryption => prompt.prompt_decryption_password(),
        }
    }
}
