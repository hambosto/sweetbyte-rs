//! Display functions for terminal output.
//!
//! Provides formatted tables for file information, success messages,
//! and the ASCII art banner for interactive mode.

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

/// Displays discovered files in a formatted table.
///
/// Shows file number, name (truncated if too long), size, and encryption status.
///
/// # Arguments
///
/// * `files` - Slice of files to display (size is queried).
///
/// # Errors
///
/// Returns an error if file metadata cannot be read.
pub fn show_file_info(files: &mut [File]) -> Result<()> {
    if files.is_empty() {
        println!("{}", console::style("No files found").yellow().bright());
        return Ok(());
    }

    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Found {} file(s):", files.len())).white().bright());
    println!();

    // Create styled table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("No").fg(Color::White), Cell::new("Name").fg(Color::White), Cell::new("Size").fg(Color::White), Cell::new("Status").fg(Color::White)]);

    // Add rows for each file
    for (i, file) in files.iter_mut().enumerate() {
        let filename = file.path().file_name().and_then(|n| n.to_str()).unwrap_or("unknown");

        // Truncate long filenames
        let display_name = if filename.len() > 25 { format!("{}...", &filename[..22]) } else { filename.to_owned() };

        // Determine encryption status
        let (status_text, status_color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };

        let size = file.size()?;

        table.add_row(vec![Cell::new(i + 1), Cell::new(&display_name).fg(Color::Green), Cell::new(ByteSize(size).to_string()), Cell::new(status_text).fg(status_color)]);
    }

    println!("{table}");
    println!();
    Ok(())
}

/// Displays a success message after processing completes.
///
/// # Arguments
///
/// * `mode` - The operation that completed.
/// * `path` - The path to the processed file.
pub fn show_success(mode: ProcessorMode, path: &Path) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("File {} successfully: {}", action, filename)).white().bright());
}

/// Displays a message after source file deletion.
///
/// # Arguments
///
/// * `path` - The path to the deleted file.
pub fn show_source_deleted(path: &Path) {
    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Source file deleted: {}", filename)).white().bright());
}

/// Clears the terminal screen.
pub fn clear_screen() -> Result<()> {
    let term = Term::stdout();
    term.clear_screen().map_err(|e| anyhow!("failed to clear screen: {e}"))?;
    Ok(())
}

/// Prints the application banner using FIGlet font.
///
/// Loads the rectangles font from embedded assets and displays
/// the application name in large ASCII art.
pub fn print_banner() -> Result<()> {
    // Load FIGlet font from embedded assets
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow!("failed to load font: {e}"))?;

    // Convert text to FIGlet output
    let fig = font.convert(APP_NAME).ok_or_else(|| anyhow!("failed to convert text to banner"))?;

    // Print with green styling
    println!("{}", console::style(fig).green().bright());
    Ok(())
}
