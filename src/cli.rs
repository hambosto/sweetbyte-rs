//! Command Line Interface Module
//!
//! This module handles all command-line argument parsing, validation, and execution
//! flow for the SweetByte encryption tool. It provides both direct command execution
//! and interactive modes for user convenience.
//!
//! ## Architecture
//!
//! The CLI module follows a clean separation of concerns:
//! - **Argument Parsing**: Uses clap for robust command-line parsing with validation
//! - **Execution Flow**: Orchestrates the encryption/decryption workflow
//! - **User Interaction**: Handles password prompts and file selection in interactive mode
//!
//! ## Security Considerations
//!
//! The CLI module implements several security measures:
//! - Password length validation prevents weak passwords
//! - File existence checks prevent accidental overwrites
//! - Input validation prevents path traversal attacks
//! - Secure password prompting avoids command-line exposure

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};

use crate::config::PASSWORD_MIN_LENGTH;
use crate::file::File;
use crate::processor::Processor;
use crate::types::{Processing, ProcessorMode};
use crate::ui::prompt::Prompt;

/// Available command-line subcommands
///
/// This enum defines the primary operations supported by SweetByte. Each variant
/// represents a distinct mode of operation with its own set of arguments.
#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file with AES-256-GCM or XChaCha20-Poly1305
    ///
    /// ## Arguments
    ///
    /// * `input` - Path to the source file to encrypt
    /// * `output` - Optional output path. If not provided, uses input + .swx extension
    /// * `password` - Optional password. If not provided, will prompt securely
    ///
    /// ## Security Notes
    ///
    /// - Providing passwords via command line is **not recommended** as they may
    ///   be visible in process lists and shell history
    /// - The tool will generate a unique salt for each encryption operation
    /// - Output files include integrity verification through authenticated encryption
    Encrypt {
        /// Input file path to encrypt
        #[arg(short, long)]
        input: String,

        /// Optional output file path (defaults to input + .swx)
        #[arg(short, long)]
        output: Option<String>,

        /// Optional password (not recommended - use prompt instead)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a previously encrypted file
    ///
    /// ## Arguments
    ///
    /// * `input` - Path to the encrypted .swx file
    /// * `output` - Optional output path. If not provided, strips .swx extension
    /// * `password` - Optional password. If not provided, will prompt securely
    ///
    /// ## Security Notes
    ///
    /// - Decryption will fail if the password is incorrect or the file is corrupted
    /// - The tool performs integrity verification using the embedded MAC
    /// - Original filename and metadata are restored from the encrypted header
    Decrypt {
        /// Input encrypted file path (.swx file)
        #[arg(short, long)]
        input: String,

        /// Optional output file path (defaults to input without .swx)
        #[arg(short, long)]
        output: Option<String>,

        /// Optional password (not recommended - use prompt instead)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Launch interactive mode for guided file operations
    ///
    /// Interactive mode provides a user-friendly interface with:
    /// - File browser for selecting input files
    /// - Mode selection (encrypt/decrypt)
    /// - Secure password prompts
    /// - Confirmation dialogs for destructive operations
    /// - Automatic file cleanup options
    Interactive,
}

/// Main command-line interface structure
///
/// This struct defines the top-level CLI configuration and serves as the entry
/// point for all command-line operations. It integrates with clap for automatic
/// help generation, argument validation, and error handling.
///
/// ## Features
///
/// - **Automatic Help**: `--help` displays comprehensive usage information
/// - **Version Info**: `--version` shows the current application version
/// - **Error Handling**: Provides clear error messages for invalid inputs
/// - **Interactive Mode**: Falls back to interactive mode if no subcommand provided
#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    /// Optional subcommand to execute
    ///
    /// If no subcommand is provided, the application will launch in interactive mode.
    /// This design choice ensures a good user experience for both power users
    /// (who prefer direct commands) and casual users (who benefit from guidance).
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    /// Initialize the CLI by parsing command-line arguments
    ///
    /// This method leverages clap's derive macros to automatically parse
    /// and validate command-line arguments. It will exit the process
    /// with appropriate error codes if parsing fails.
    ///
    /// # Returns
    ///
    /// Returns a configured `Cli` instance ready for execution.
    pub fn init() -> Self {
        Self::parse()
    }

    /// Execute the parsed command or launch interactive mode
    ///
    /// This is the main execution dispatcher that routes to the appropriate
    /// handler based on the parsed command. It ensures proper error handling
    /// and provides a consistent user experience across all modes.
    ///
    /// # Arguments
    ///
    /// * `self` - The parsed CLI configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successful execution
    /// * `Err(anyhow::Error)` - Execution failed with error context
    ///
    /// # Security Considerations
    ///
    /// - All password operations go through the secure prompt interface
    /// - File operations are validated before execution
    /// - Error messages are sanitized to avoid information leakage
    pub fn execute(self) -> Result<()> {
        // Initialize the secure password prompt with minimum length validation
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);

        // Route to the appropriate execution handler
        match self.command {
            Some(Commands::Encrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Encryption, &prompt),
            Some(Commands::Decrypt { input, output, password }) => Self::run_mode(input, output, password, Processing::Decryption, &prompt),
            Some(Commands::Interactive) | None => Self::run_interactive(&prompt),
        }
    }

    /// Execute direct (non-interactive) encryption or decryption
    ///
    /// This method handles the direct command-line mode where all parameters
    /// are provided explicitly. It performs validation, password handling,
    /// and executes the requested operation.
    ///
    /// # Arguments
    ///
    /// * `input_path` - Path to the input file
    /// * `output_path` - Optional output path (auto-generated if not provided)
    /// * `password` - Optional password (will prompt if not provided)
    /// * `processing` - Whether to encrypt or decrypt
    /// * `prompt` - Secure password prompt interface
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Operation completed successfully
    /// * `Err(anyhow::Error)` - Operation failed with context
    ///
    /// # Security Notes
    ///
    /// - Output path validation prevents accidental overwrites
    /// - Password prompting avoids command-line exposure
    /// - Input file validation ensures file exists and is readable
    fn run_mode(input_path: String, output_path: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<()> {
        // Create and validate input file
        let mut input = File::new(input_path);

        // Generate output path if not provided, ensuring proper extension handling
        let output = File::new(output_path.unwrap_or_else(|| input.output_path(processing.mode()).to_string_lossy().into_owned()));

        // Handle password securely - prompt if not provided via command line
        let password = password.map(Ok).unwrap_or_else(|| Self::get_password(prompt, processing))?;

        // Execute the processing operation with proper error context
        Self::process(processing, &mut input, &output, &password)?;

        // Display success message to user
        crate::ui::show_success(processing.mode(), output.path());

        Ok(())
    }

    /// Execute interactive mode with guided user workflow
    ///
    /// Interactive mode provides a user-friendly interface with step-by-step
    /// guidance through the encryption/decryption process. It includes file
    /// browsing, confirmation dialogs, and optional cleanup operations.
    ///
    /// # Arguments
    ///
    /// * `prompt` - Secure prompt interface for user interactions
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Interactive session completed successfully
    /// * `Err(anyhow::Error)` - Session failed or was canceled
    ///
    /// # Interactive Workflow
    ///
    /// 1. Display welcome banner and clear screen
    /// 2. Prompt for processing mode (encrypt/decrypt)
    /// 3. Discover and display eligible files
    /// 4. Allow user to select target file
    /// 5. Validate selected file and determine output path
    /// 6. Confirm overwrite if output file exists
    /// 7. Securely prompt for password
    /// 8. Execute the operation
    /// 9. Display results and offer cleanup options
    ///
    /// # Security Features
    ///
    /// - File discovery excludes system directories and encrypted files as appropriate
    /// - Overwrite confirmation prevents accidental data loss
    /// - Optional secure deletion of source files after successful operations
    fn run_interactive(prompt: &Prompt) -> Result<()> {
        // Prepare the interactive environment
        crate::ui::clear_screen()?;
        crate::ui::print_banner()?;

        // Step 1: Select processing mode (encrypt/decrypt)
        let mode = prompt.select_processing_mode()?;
        let processing = match mode {
            ProcessorMode::Encrypt => Processing::Encryption,
            ProcessorMode::Decrypt => Processing::Decryption,
        };

        // Step 2: Discover eligible files in current directory and subdirectories
        let mut files = File::discover(mode);
        ensure!(!files.is_empty(), "no eligible files found");

        // Step 3: Display file information and let user select
        crate::ui::show_file_info(&mut files)?;

        // Step 4: Get user's file selection and validate it
        let path = prompt.select_file(&files)?;
        let mut input = File::new(path.to_string_lossy().into_owned());
        input.validate(true)?; // Ensure file exists and is readable

        // Step 5: Determine output path based on processing mode
        let output = File::new(input.output_path(mode).to_string_lossy().into_owned());

        // Step 6: Prevent accidental overwrites with confirmation
        if output.exists() && !prompt.confirm_file_overwrite(output.path())? {
            bail!("operation canceled");
        }

        // Step 7: Securely obtain password from user
        let password = Self::get_password(prompt, processing)?;

        // Step 8: Execute the encryption/decryption operation
        Self::process(processing, &mut input, &output, &password)?;

        // Step 9: Display success information
        crate::ui::show_success(mode, output.path());

        // Step 10: Offer optional secure cleanup of source file
        let label = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };
        if prompt.confirm_file_deletion(input.path(), label)? {
            input.delete()?;
            crate::ui::show_source_deleted(input.path());
        }

        Ok(())
    }

    /// Execute the core encryption/decryption operation
    ///
    /// This is a thin wrapper around the `Processor` that provides
    /// consistent error handling and context information across both
    /// direct and interactive modes.
    ///
    /// # Arguments
    ///
    /// * `processing` - The operation type (encryption or decryption)
    /// * `input` - Input file reference (must be validated)
    /// * `output` - Output file reference
    /// * `password` - The user's password for key derivation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Operation completed successfully
    /// * `Err(anyhow::Error)` - Operation failed with detailed context
    ///
    /// # Error Handling
    ///
    /// All errors are wrapped with context information including:
    /// - The type of operation that failed
    /// - The input file path for debugging
    /// - The underlying error from the processor
    fn process(processing: Processing, input: &mut File, output: &File, password: &str) -> Result<()> {
        // Create processor with the user-provided password
        let processor = Processor::new(password);

        // Execute the appropriate operation based on processing type
        let result = match processing {
            Processing::Encryption => processor.encrypt(input, output),
            Processing::Decryption => processor.decrypt(input, output),
        };

        // Add context to any errors for better debugging
        result.with_context(|| format!("{} failed: {}", processing, input.path().display()))
    }

    /// Get password from user with appropriate prompt for operation type
    ///
    /// This method routes to the correct prompt method based on whether
    /// we're encrypting or decrypting, ensuring the user sees the right
    /// contextual information.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The secure prompt interface
    /// * `processing` - The operation type to determine prompt style
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The password entered by the user
    /// * `Err(anyhow::Error)` - Password entry failed or was canceled
    ///
    /// # Security Notes
    ///
    /// - Passwords are never echoed to the terminal
    /// - Passwords are not stored in command history
    /// - Memory is zeroized after use by the prompt implementation
    fn get_password(prompt: &Prompt, processing: Processing) -> Result<String> {
        match processing {
            Processing::Encryption => prompt.prompt_encryption_password(),
            Processing::Decryption => prompt.prompt_decryption_password(),
        }
    }
}
