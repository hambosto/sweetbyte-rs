use anyhow::{Context, Result, bail, ensure};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::{Decryptor, Encryptor};
use crate::types::{Processing, ProcessorMode};
use crate::ui::display::*;
use crate::ui::prompt::Prompt;

/// Command-line interface struct for SweetByte encryption tool.
///
/// Parses and validates command-line arguments, then dispatches to the
/// appropriate processing mode. Supports encrypt, decrypt, interactive,
/// and shell completion subcommands.
#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    /// Optional subcommand to execute. If None, runs in interactive mode.
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    /// Initializes the CLI by parsing command-line arguments.
    ///
    /// # Returns
    /// A new Cli instance with parsed arguments.
    pub fn init() -> Self {
        Self::parse()
    }

    /// Executes the CLI command or enters interactive mode.
    ///
    /// If a subcommand is provided, it executes that command. Otherwise,
    /// it runs in interactive mode with a terminal-based UI.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the operation failed.
    pub fn execute(self) -> Result<()> {
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);

        match self.command {
            Some(cmd) => cmd.run(&prompt),
            None => run_interactive(&prompt),
        }
    }
}

/// Enum representing the available CLI subcommands.
///
/// Each variant corresponds to a specific operation: encrypt files,
/// decrypt files, run in interactive mode, or generate shell completions.
#[derive(Subcommand)]
pub enum Commands {
    /// Encrypts a file with password-based encryption.
    Encrypt {
        /// Path to the input file to encrypt.
        #[arg(short, long)]
        input: String,
        /// Optional path for the encrypted output file.
        #[arg(short, long)]
        output: Option<String>,
        /// Optional password (prompts if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypts an encrypted file.
    Decrypt {
        /// Path to the encrypted input file.
        #[arg(short, long)]
        input: String,
        /// Optional path for the decrypted output file.
        #[arg(short, long)]
        output: Option<String>,
        /// Optional password (prompts if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Runs the application in interactive TUI mode.
    Interactive,

    /// Generates shell completion scripts.
    Completions {
        /// The shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    /// Runs the specified subcommand.
    ///
    /// Dispatches to the appropriate processing function based on the command type.
    ///
    /// # Arguments
    /// * `prompt` - The Prompt instance for password input.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the operation failed.
    pub fn run(self, prompt: &Prompt) -> Result<()> {
        match self {
            Self::Encrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Encryption, prompt),
            Self::Decrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Decryption, prompt),
            Self::Interactive => run_interactive(prompt),
            Self::Completions { shell } => {
                generate_completions(shell);
                Ok(())
            }
        }
    }
}

/// Handles CLI-based file processing (non-interactive).
///
/// Reads command-line arguments, resolves the output path, obtains the password,
/// and processes the file.
///
/// # Arguments
/// * `input_path` - Path to the input file.
/// * `output_path` - Optional output path, or auto-generated if None.
/// * `password` - Optional password, or prompted if None.
/// * `processing` - The processing operation (encryption or decryption).
/// * `prompt` - The Prompt instance for password input.
///
/// # Returns
/// Ok(()) on success, or an error if the operation failed.
fn run_cli_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
    // Create File instance for input and auto-generate output path if not provided.
    let mut input = File::new(input_path);
    let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));

    // Prompt for password if not provided via command line.
    let password = match password {
        Some(pwd) => pwd,
        None => prompt_password(prompt, processing)?,
    };

    // Process the file and print the result.
    process_file(processing, &mut input, &output, &password)?;
    println!("✓ {}: {} -> {}", processing, input.path().display(), output.path().display());

    Ok(())
}

/// Handles interactive TUI-based file processing.
///
/// Displays a banner, prompts for the processing mode, discovers eligible files,
/// allows file selection, prompts for password confirmation, and processes the file.
/// Optionally prompts to delete the source file after successful processing.
///
/// # Arguments
/// * `prompt` - The Prompt instance for user interaction.
///
/// # Returns
/// Ok(()) on success, or an error if the operation failed.
fn run_interactive(prompt: &Prompt) -> Result<()> {
    clear_screen()?;
    print_banner()?;

    // Prompt user to select encryption or decryption mode.
    let mode = prompt.select_processing_mode()?;
    let input = select_file(prompt, mode)?;
    let processing = match mode {
        ProcessorMode::Encrypt => Processing::Encryption,
        ProcessorMode::Decrypt => Processing::Decryption,
    };

    // Validate the input file exists and is not empty.
    let mut input_file = File::new(input.path().to_string_lossy().into_owned());
    input_file.validate(true)?;

    // Determine output path and check for overwrite if file exists.
    let output = File::new(input_file.output_path(processing.mode()).to_string_lossy().into_owned());
    if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
        bail!("operation canceled");
    }

    // Prompt for password.
    let password = prompt_password(prompt, processing)?;
    process_file(processing, &mut input_file, &output, &password)?;

    // Show success message and optionally delete source file.
    show_success(mode, output.path());
    delete_source(prompt, &input_file, processing.mode())?;

    Ok(())
}

/// Processes a file using the specified operation.
///
/// Creates an Encryptor or Decryptor based on the processing type and
/// delegates the file processing to it.
///
/// # Arguments
/// * `processing` - The processing operation (encryption or decryption).
/// * `input` - The input File to process.
/// * `output` - The output File to write to.
/// * `password` - The password for encryption/decryption.
///
/// # Returns
/// Ok(()) on success, or an error if the operation failed.
fn process_file(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
    match processing {
        Processing::Encryption => Encryptor::new(password).encrypt(input, output),
        Processing::Decryption => Decryptor::new(password).decrypt(input, output),
    }
    .with_context(|| format!("{} failed: {}", processing, input.path().display()))
}

/// Prompts for a password based on the processing type.
///
/// For encryption, uses the encryption password prompt; for decryption,
/// uses the decryption password prompt.
///
/// # Arguments
/// * `prompt` - The Prompt instance for password input.
/// * `processing` - The processing operation.
///
/// # Returns
/// The password string from user input.
fn prompt_password(prompt: &Prompt, processing: Processing) -> Result<String> {
    match processing {
        Processing::Encryption => prompt.prompt_encryption_password(),
        Processing::Decryption => prompt.prompt_decryption_password(),
    }
}

/// Discovers and selects a file for processing.
///
/// Finds eligible files in the current directory, displays them in a table,
/// and prompts the user to select one.
///
/// # Arguments
/// * `prompt` - The Prompt instance for file selection.
/// * `mode` - The processor mode for filtering eligible files.
///
/// # Returns
/// The selected File, or an error if no files found.
fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<File> {
    let mut files: Vec<File> = File::discover(mode);
    ensure!(!files.is_empty(), "no eligible files found");

    show_file_info(&mut files)?;
    let path = prompt.select_file(&files)?;
    Ok(File::new(path.to_string_lossy().into_owned()))
}

/// Optionally deletes the source file after successful processing.
///
/// Prompts the user for confirmation before deletion.
///
/// # Arguments
/// * `prompt` - The Prompt instance for confirmation.
/// * `file` - The file to potentially delete.
/// * `mode` - The processor mode (determines the label used in prompts).
///
/// # Returns
/// Ok(()) regardless of deletion, or an error if deletion failed.
fn delete_source(prompt: &Prompt, file: &File, mode: ProcessorMode) -> Result<()> {
    // Determine the appropriate label based on the operation.
    let label = if mode == ProcessorMode::Encrypt { "original" } else { "encrypted" };

    // Prompt for deletion confirmation and delete if confirmed.
    if prompt.confirm_file_deletion(file.path(), label)? {
        file.delete()?;
        show_source_deleted(file.path());
    }
    Ok(())
}

/// Generates shell completion scripts.
///
/// Uses clap_complete to generate shell-specific completion scripts
/// for the sweetbyte-rs CLI.
///
/// # Arguments
/// * `shell` - The shell to generate completions for.
fn generate_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sweetbyte-rs", &mut std::io::stdout());
}
