//! # User Interface Module
//!
//! This module provides the complete user interface layer for the SweetByte application,
//! handling all user-facing interactions, visual feedback, and terminal operations.
//!
//! ## Architecture
//!
//! The UI module is organized into three main components:
//!
//! - **Display Functions** (`mod.rs`): Core presentation logic for file information, success
//!   messages, banners, and formatted output tables
//! - **Progress Tracking** (`progress.rs`): Real-time progress bars with performance metrics and
//!   terminal-safe rendering
//! - **User Input** (`prompt.rs`): Interactive prompts for passwords, file selection, and user
//!   confirmations with security considerations
//!
//! ## Design Principles
//!
//! - **User Experience**: Clear, consistent visual feedback throughout all operations
//! - **Terminal Safety**: Proper handling of terminal state and cursor management
//! - **Accessibility**: Color-coded information with fallbacks for different terminals
//! - **Security**: Secure password input with no echoing or storage in plain text
//!
//! ## Dependencies
//!
//! - `comfy_table`: Rich table formatting with Unicode support
//! - `console`: Terminal styling and screen management
//! - `figlet_rs`: ASCII art banner generation
//! - `bytesize`: Human-readable file size formatting

use std::path::Path;

use anyhow::{Result, anyhow};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::Term;
use figlet_rs::FIGfont;

use crate::config::APP_NAME;
use crate::file::File;
use crate::types::ProcessorMode;

pub mod progress;
pub mod prompt;

/// Display formatted file information in a table
///
/// This function presents discovered files in a user-friendly table format,
/// showing file number, name, size, and encryption status. The table uses
/// Unicode borders and color coding for enhanced readability.
///
/// # Arguments
///
/// * `files` - Mutable slice of File objects to display. Mutable because we need to check
///   encryption status which may trigger lazy loading
///
/// # Returns
///
/// * `Result<()>` - Success or error if file operations fail
///
/// # Errors
///
/// * If unable to retrieve file size or status information
///
/// # UI/UX Considerations
///
/// - Shows clear warning message for empty file lists
/// - Uses color-coded status indicators (green for unencrypted, cyan for encrypted)
/// - Truncates long filenames to maintain table readability
/// - Provides numbered selection for easy user reference
/// - Uses dynamic content arrangement to handle varying terminal widths
pub fn show_file_info(files: &mut [File]) -> Result<()> {
    // Handle empty file list with appropriate user feedback
    if files.is_empty() {
        println!("{}", console::style("No files found").yellow().bright());
        return Ok(());
    }

    // Add visual separation before the file table
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Found {} file(s):", files.len())).white().bright());
    println!();

    // Create a styled table with full Unicode borders and rounded corners
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("No").fg(Color::White), Cell::new("Name").fg(Color::White), Cell::new("Size").fg(Color::White), Cell::new("Status").fg(Color::White)]);

    // Populate table with file information
    for (i, file) in files.iter_mut().enumerate() {
        // Extract filename safely, fallback to "unknown" if parsing fails
        let filename = file.path().file_name().and_then(|n| n.to_str()).unwrap_or("unknown");

        // Truncate long filenames to maintain table layout (25 char limit)
        let display_name = if filename.len() > 25 { format!("{}...", &filename[..22]) } else { filename.to_owned() };

        // Determine encryption status with color coding for quick visual identification
        let (status_text, status_color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };

        // Get file size and format for human-readable display
        let size = file.size()?;

        // Add row with color-coded information
        table.add_row(vec![
            Cell::new(i + 1),                          // File number for selection
            Cell::new(&display_name).fg(Color::Green), // Filename in green
            Cell::new(ByteSize(size).to_string()),     // Human-readable size
            Cell::new(status_text).fg(status_color),   // Status with appropriate color
        ]);
    }

    // Display the formatted table
    println!("{table}");
    println!();

    Ok(())
}

/// Display success message for file operations
///
/// Shows a formatted success message after successful encryption or decryption
/// operations. Uses color coding and checkmarks for positive reinforcement.
///
/// # Arguments
///
/// * `mode` - The processor mode (Encrypt/Decrypt) that was completed
/// * `path` - Path to the processed file
///
/// # UI/UX Considerations
///
/// - Provides clear feedback about operation completion
/// - Uses consistent checkmark and color scheme with other success messages
/// - Shows the actual filename for user confirmation
/// - Maintains visual hierarchy with spacing and styling
pub fn show_success(mode: ProcessorMode, path: &Path) {
    // Convert mode to human-readable action text
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    // Extract filename safely with fallback to full path
    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

    // Display formatted success message with visual indicators
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("File {action} successfully: {filename}")).white().bright());
}

/// Display confirmation message for source file deletion
///
/// Shows a confirmation message when the source file is successfully deleted
/// after an operation (e.g., when cleanup is enabled).
///
/// # Arguments
///
/// * `path` - Path to the deleted source file
///
/// # UI/UX Considerations
///
/// - Confirms destructive operations to maintain user trust
/// - Uses same visual style as other success messages for consistency
/// - Helps users understand what happened to their files
pub fn show_source_deleted(path: &Path) {
    // Extract filename safely with fallback to full path
    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

    // Display deletion confirmation with visual indicators
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Source file deleted: {filename}")).white().bright());
}

/// Clear the terminal screen
///
/// Provides a safe way to clear the terminal screen, handling potential
/// errors gracefully. Useful for creating clean interfaces between operations.
///
/// # Returns
///
/// * `Result<()>` - Success or error if screen clearing fails
///
/// # Errors
///
/// * If terminal operations fail (e.g., not a real terminal, permissions)
///
/// # UI/UX Considerations
///
/// - Used sparingly to avoid disorienting users
/// - Helps create clean separation between major UI sections
/// - Provides error context if terminal operations fail
pub fn clear_screen() -> Result<()> {
    // Get handle to standard output terminal
    let term = Term::stdout();

    // Clear screen with proper error handling and context
    term.clear_screen().map_err(|e| anyhow!("failed to clear screen: {e}"))?;

    Ok(())
}

/// Display header information from encrypted files
///
/// Shows metadata stored in encrypted file headers, including the original
/// filename, size, and checksum hash. This helps users verify file integrity
/// before decryption operations.
///
/// # Arguments
///
/// * `filename` - Original filename stored in the header
/// * `size` - Original file size in bytes
/// * `hash` - SHA256 hash bytes of the original file data
///
/// # UI/UX Considerations
///
/// - Critical for security verification before decryption
/// - Uses color coding to separate labels from values
/// - Displays hash in hexadecimal for easy comparison
/// - Maintains consistent table styling with other displays
pub fn show_header_info(filename: &str, size: u64, hash: &[u8]) {
    // Add visual separation before header information
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style("Header Information:").bold());

    // Convert hash bytes to hexadecimal string for display
    // Each byte becomes two hex characters (e.g., 0xAB -> "ab")
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    // Create formatted table for header metadata
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);

    // Add rows with color-coded labels and values
    table.add_row(vec![Cell::new("Original Filename").fg(Color::Green), Cell::new(filename).fg(Color::White)]);
    table.add_row(vec![Cell::new("Original Size").fg(Color::Green), Cell::new(ByteSize(size).to_string()).fg(Color::White)]);
    table.add_row(vec![Cell::new("Original Hash").fg(Color::Green), Cell::new(hash_hex).fg(Color::White)]);

    // Display the header information table
    print!("{table}");
}

/// Display application banner using ASCII art
///
/// Creates and displays a stylized ASCII art banner for the application
/// using a custom font. This provides visual branding and helps users
/// identify the application they're using.
///
/// # Returns
///
/// * `Result<()>` - Success or error if banner creation fails
///
/// # Errors
///
/// * If font loading from assets fails
/// * If text-to-ASCII conversion fails
/// * If the font file is missing or corrupted
///
/// # UI/UX Considerations
///
/// - Provides professional appearance and branding
/// - Uses embedded assets to avoid external dependencies
/// - Consistent color scheme with green theme
/// - Helps create memorable user experience
///
/// # Performance Notes
///
/// Font content is embedded at compile time using `include_str!`,
/// avoiding runtime file I/O and ensuring the banner is always available.
pub fn print_banner() -> Result<()> {
    // Load custom ASCII font from embedded asset
    // Using include_str! ensures the font is compiled into the binary
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow!("failed to load font: {e}"))?;

    // Convert application name to ASCII art using the loaded font
    let fig = font.convert(APP_NAME).ok_or_else(|| anyhow!("failed to convert text to banner"))?;

    // Display the banner with consistent green styling
    println!("{}", console::style(fig).green().bright());

    Ok(())
}
