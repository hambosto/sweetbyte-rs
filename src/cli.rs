//! Command-line interface for SweetByte.
//!
//! Provides both interactive and command-line modes for encrypting and decrypting files.
//! Uses [`clap`] for argument parsing and [`dialoguer`] for interactive prompts.
//!
//! # Commands
//!
//! - `encrypt` - Encrypt a file with password protection
//! - `decrypt` - Decrypt an encrypted file
//! - `interactive` - Launch the wizard-style interface
//! - `completions` - Generate shell completion scripts

use anyhow::{Context, Result, bail, ensure};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::{Decryptor, Encryptor};
use crate::types::{Processing, ProcessorMode};
use crate::ui::display::*;
use crate::ui::prompt::Prompt;

/// Command-line argument parser for SweetByte.
///
/// Parses user input and routes to the appropriate processing mode.
/// When run without subcommands, launches interactive mode.
#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    /// The subcommand to execute (encrypt, decrypt, interactive, completions).
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    /// Creates a new CLI instance by parsing command-line arguments.
    ///
    /// Uses [`clap`]'s automatic argument parsing from `std::env::args()`.
    /// The arguments are automatically parsed from sys::env based on the
    /// struct derive attributes (Parser, command, arg).
    #[inline]
    pub fn init() -> Self {
        Self::parse()
    }

    /// Executes the requested command or launches interactive mode.
    ///
    /// Initializes a Prompt handler with the configured minimum password length,
    /// then either executes the specified subcommand or falls back to interactive
    /// wizard mode. Errors are propagated with contextual information.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails, with contextual information
    /// about what went wrong.
    pub fn execute(self) -> Result<()> {
        // Initialize prompt handler with minimum password length requirement
        // This will be used for all password interactions in this session
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);

        // Check if a subcommand was provided on command line
        // If yes, execute that command; if no, launch interactive mode
        match self.command {
            Some(cmd) => cmd.run(&prompt),
            None => run_interactive(&prompt),
        }
    }
}

/// Available subcommands for the CLI.
///
/// Each variant corresponds to a different operation mode.
/// The struct fields are automatically mapped to CLI arguments
/// by the clap derive macro.
#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file with password protection.
    Encrypt {
        /// Path to the input file to encrypt.
        #[arg(short, long)]
        input: String,

        /// Path for the output encrypted file (auto-derived if not specified).
        /// If omitted, the output path is derived by appending `.swx` to input.
        #[arg(short, long)]
        output: Option<String>,

        /// Password for encryption (prompts if not provided).
        /// Providing password on command line is convenient but less secure.
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt an encrypted file.
    Decrypt {
        /// Path to the encrypted input file.
        #[arg(short, long)]
        input: String,

        /// Path for the output decrypted file (auto-derived if not specified).
        /// If omitted, the `.swx` extension is removed from input path.
        #[arg(short, long)]
        output: Option<String>,

        /// Password for decryption (prompts if not provided).
        /// The password must match the one used for encryption.
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Launch the interactive wizard mode.
    ///
    /// Provides a guided experience with file selection, password prompts,
    /// and confirmation dialogs without requiring command-line arguments.
    Interactive,

    /// Generate shell completion scripts.
    ///
    /// Outputs shell completion code for the specified shell to stdout.
    /// This enables tab completion for sweetbyte-rs commands.
    Completions {
        /// The shell to generate completions for.
        /// Supported shells: bash, zsh, fish, powershell, elvish
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    /// Runs the specified subcommand.
    ///
    /// Dispatches to the appropriate handler function based on the command type.
    /// Each handler manages the complete workflow for that operation.
    ///
    /// # Arguments
    ///
    /// * `prompt` - Reference to the Prompt handler for user interactions.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run(self, prompt: &Prompt) -> Result<()> {
        // Pattern match on the command variant to determine which handler to call
        // Each branch extracts the relevant fields and passes them to the handler
        match self {
            // Encrypt command: extract fields and call CLI mode handler
            Self::Encrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Encryption, prompt),
            // Decrypt command: extract fields and call CLI mode handler
            Self::Decrypt { input, output, password } => run_cli_mode(input, output, password, Processing::Decryption, prompt),
            // Interactive command: launch wizard mode
            Self::Interactive => run_interactive(prompt),
            // Completions command: generate and print shell completions
            Self::Completions { shell } => {
                generate_completions(shell);
                Ok(())
            }
        }
    }
}

/// Handles command-line mode encryption/decryption.
///
/// This is the core function for non-interactive CLI usage. It:
/// 1. Creates File instances for input and output
/// 2. Prompts for password if not provided
/// 3. Processes the file through the encryption/decryption pipeline
/// 4. Displays success message
///
/// # Arguments
///
/// * `input_path` - Path to the input file as a String.
/// * `output_path` - Optional path for the output file.
/// * `password` - Optional password provided on command line.
/// * `processing` - Processing type (Encryption or Decryption).
/// * `prompt` - Reference to the Prompt handler.
///
/// # Errors
///
/// Returns an error if file operations or processing fails.
fn run_cli_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
    // Create File instance for input path
    // The File struct wraps PathBuf and provides helper methods
    let mut input = File::new(input_path);

    // Determine output path: use provided path or auto-derive from input
    // The closure is only executed if output_path is None, avoiding unnecessary work
    // Auto-derivation: append .swx for encryption, remove .swx for decryption
    let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));

    // Password handling: use provided password or prompt user
    // This allows both scripted usage (password on command line)
    // and secure usage (interactive prompt with hidden input)
    let password = match password {
        // Password was provided on command line, use it directly
        Some(pwd) => pwd,
        // No password provided, prompt user with appropriate message
        // Encryption prompts show "Enter encryption password" and confirm
        // Decryption prompts show "Enter decryption password" only
        None => prompt_password(prompt, processing)?,
    };

    // Process the file through the encryption/decryption pipeline
    // This handles all the cryptographic operations, header creation/parsing,
    // chunked processing with parallel execution, and I/O
    process_file(processing, &mut input, &output, &password)?;

    // Display success message with styled output
    // Shows a green checkmark and the action + filename
    show_success(processing.mode(), output.path());

    Ok(())
}

/// Handles interactive mode with wizard-style interface.
///
/// This function provides a guided experience for users who prefer
/// not to use command-line arguments. It handles:
/// 1. Clearing the screen and displaying the banner
/// 2. Prompting for operation mode (encrypt/decrypt)
/// 3. Discovering and displaying eligible files
/// 4. Prompting for file selection
/// 5. Confirming output file overwrite if needed
/// 6. Prompting for password
/// 7. Processing the file
/// 8. Optionally deleting the source file
///
/// # Arguments
///
/// * `prompt` - Reference to the Prompt handler for all user interactions.
///
/// # Errors
///
/// Returns an error if user input fails or file operations fail.
fn run_interactive(prompt: &Prompt) -> Result<()> {
    // Clear the terminal screen for a clean display
    // This removes any previous output for a fresh experience
    clear_screen()?;

    // Display the FIGlet ASCII art banner showing the application name
    // Uses the rectangles font from embedded assets
    print_banner()?;

    // Step 1: Prompt user to select processing mode (encrypt or decrypt)
    // Displays a selection menu with "Encrypt" and "Decrypt" options
    let mode = prompt.select_processing_mode()?;

    // Step 2: Discover eligible files and prompt for selection
    // Files are filtered based on the selected mode:
    // - For encryption: show unencrypted files (no .swx extension)
    // - For decryption: show encrypted files (.swx extension)
    let input = select_file(prompt, mode)?;

    // Convert the selected path Processing enum variant
    // This determines which encryption/decryption pipeline to use
    let processing = match mode {
        ProcessorMode::Encrypt => Processing::Encryption,
        ProcessorMode::Decrypt => Processing::Decryption,
    };

    // Create File instance and validate it exists and is not empty
    // validate(true) checks: exists, not a directory, size > 0
    let mut input_file = File::new(input.path().to_string_lossy().into_owned());
    input_file.validate(true)?;

    // Auto-derive output path based on input path and processing mode
    // For encryption: appends .swx to input filename
    // For decryption: removes .swx extension from input filename
    let output = File::new(input_file.output_path(processing.mode()).to_string_lossy().into_owned());

    // Check if output file already exists and prompt for overwrite confirmation
    // This prevents accidental data loss from overwriting existing files
    if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
        // User chose not to overwrite, cancel the operation
        bail!("operation canceled");
    }

    // Prompt for password with appropriate validation
    // Encryption: prompts twice and ensures they match
    // Decryption: prompts once (validation happens during decryption)
    let password = prompt_password(prompt, processing)?;

    // Process the file through the encryption/decryption pipeline
    // This is the same core logic used in CLI mode
    process_file(processing, &mut input_file, &output, &password)?;

    // Display styled success message
    show_success(mode, output.path());

    // Optionally delete the source file after successful processing
    // Prompts user for confirmation before deletion
    delete_source(prompt, &input_file, processing.mode())?;

    Ok(())
}

/// Processes a single file through the encryption or decryption pipeline.
///
/// This is a thin wrapper that creates the appropriate processor
/// (Encryptor or Decryptor) and delegates the actual work.
///
/// # Arguments
///
/// * `processing` - The processing mode (encryption or decryption).
/// * `input` - The input file to process (mutable for size query).
/// * `output` - The output file destination.
/// * `password` - The password for key derivation.
///
/// # Errors
///
/// Returns an error if the processing pipeline fails.
/// The error context includes the operation type and input file path.
fn process_file(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
    // Create appropriate processor based on mode
    // Encryptor/Decryptor wrap the password and provide encrypt/decrypt methods
    match processing {
        // Encryption path: create Encryptor and call encrypt
        Processing::Encryption => Encryptor::new(password).encrypt(input, output),
        // Decryption path: create Decryptor and call decrypt
        Processing::Decryption => Decryptor::new(password).decrypt(input, output),
    }
    // Add context for better error messages
    // Shows which operation failed and which file was being processed
    .with_context(|| format!("{} failed: {}", processing, input.path().display()))
}

/// Prompts for password appropriate to the processing mode.
///
/// Routes to the appropriate prompt method based on whether we're
/// encrypting or decrypting.
///
/// # Arguments
///
/// * `prompt` - Reference to the Prompt handler.
/// * `processing` - The processing mode.
///
/// # Errors
///
/// Returns an error if password input fails validation.
fn prompt_password(prompt: &Prompt, processing: Processing) -> Result<String> {
    match processing {
        // Encryption requires password confirmation to prevent typos
        // Prompts twice and ensures both entries match
        Processing::Encryption => prompt.prompt_encryption_password(),
        // Decryption only needs single password prompt
        // Validation happens during decryption (wrong password = auth failure)
        Processing::Decryption => prompt.prompt_decryption_password(),
    }
}

/// Discovers eligible files and prompts user to select one.
///
/// Scans the current directory and subdirectories for files that match
/// the processing mode, displays them in a table, and prompts for selection.
///
/// # Arguments
///
/// * `prompt` - Reference to the Prompt handler.
/// * `mode` - Processing mode to filter eligible files.
///
/// # Errors
///
/// Returns an error if no files are found or selection fails.
fn select_file(prompt: &Prompt, mode: ProcessorMode) -> Result<File> {
    // Discover files matching the mode's eligibility criteria
    // For encryption: finds files without .swx extension
    // For decryption: finds files with .swx extension
    // Also filters out hidden files and excluded patterns
    let mut files: Vec<File> = File::discover(mode);

    // Ensure at least one file was found
    ensure!(!files.is_empty(), "no eligible files found");

    // Display discovered files in a formatted table
    // Shows: number, truncated name, size, and encryption status
    show_file_info(&mut files)?;

    // Prompt user to select a file from the displayed list
    // Returns the path of the selected file
    let path = prompt.select_file(&files)?;

    // Create and return a File instance from the selected path
    Ok(File::new(path.to_string_lossy().into_owned()))
}

/// Prompts to securely delete the source file after processing.
///
/// Asks for confirmation before deleting, then deletes the file
/// if confirmed. Displays a success message after deletion.
///
/// # Arguments
///
/// * `prompt` - Reference to the Prompt handler.
/// * `file` - The file to potentially delete.
/// * `mode` - Processing mode (determines the file type label).
///
/// # Errors
///
/// Returns an error if file deletion fails.
fn delete_source(prompt: &Prompt, file: &File, mode: ProcessorMode) -> Result<()> {
    // Determine appropriate label based on mode
    // "original" for encryption, "encrypted" for decryption
    // This makes the confirmation message clearer to the user
    let label = if mode == ProcessorMode::Encrypt { "original" } else { "encrypted" };

    // Prompt user for confirmation before deletion
    // Shows: "Delete {label} file {filename}?"
    if prompt.confirm_file_deletion(file.path(), label)? {
        // User confirmed, delete the file
        file.delete()?;
        // Display confirmation of deletion
        show_source_deleted(file.path());
    }
    Ok(())
}

/// Generates shell completion scripts for the specified shell.
///
/// Uses clap_complete to generate completion code for the given shell
/// and prints it to stdout. Users can redirect this to their shell's
/// completion file to enable tab completion.
///
/// # Arguments
///
/// * `shell` - The shell to generate completions for.
fn generate_completions(shell: Shell) {
    // Get the clap Command struct (populated by derive macros)
    let mut cmd = Cli::command();

    // Generate completions for the specified shell
    // Writes directly to stdout for easy piping/redirecting
    clap_complete::generate(shell, &mut cmd, "sweetbyte-rs", &mut std::io::stdout());
}
