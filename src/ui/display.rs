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
/// Shows file number, name (truncated if needed), size, and encryption status.
///
/// # Arguments
/// * `files` - Slice of File instances to display.
///
/// # Returns
/// Ok(()) on success, or an error if file size query failed.
pub fn show_file_info(files: &mut [File]) -> Result<()> {
    if files.is_empty() {
        println!("{}", console::style("No files found").yellow().bright().bold());
        return Ok(());
    }

    println!();
    println!("{} {}", console::style("✔").green().bright().bold(), console::style(format!("Found {} file(s):", files.len())).white().bright().bold());
    println!();

    // Configure the table with UTF-8 formatting.
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("No").fg(Color::White), Cell::new("Name").fg(Color::White), Cell::new("Size").fg(Color::White), Cell::new("Status").fg(Color::White)]);

    // Add rows for each file.
    for (i, file) in files.iter_mut().enumerate() {
        // Extract filename from path.
        let filename = file.path().file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        // Truncate long filenames for display.
        let display_name = if filename.len() > 25 { format!("{}...", &filename[..22]) } else { filename.to_owned() };
        // Determine status based on encryption state.
        let (status_text, status_color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };
        // Get file size.
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
/// * `mode` - The processor mode (determines the action word).
/// * `path` - The path to the processed file.
pub fn show_success(mode: ProcessorMode, path: &Path) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    println!();
    println!("{} {}", console::style("✔").green().bright().bold(), console::style(format!("File {} successfully: {}", action, path.display())).white().bright().bold());
}

/// Displays a message after source file deletion.
///
/// # Arguments
/// * `path` - The path to the deleted file.
pub fn show_source_deleted(path: &Path) {
    println!("{} {}", console::style("✔").green().bright().bold(), console::style(format!("Source file deleted: {}", path.display())).white().bright().bold());
}

/// Clears the terminal screen.
///
/// # Returns
/// Ok(()) on success, or an error if clearing failed.
pub fn clear_screen() -> Result<()> {
    let term = Term::stdout();
    term.clear_screen().map_err(|e| anyhow!("failed to clear screen: {e}"))
}

/// Prints the application banner using FIGlet fonts.
///
/// # Returns
/// Ok(()) on success, or an error if font loading or conversion failed.
pub fn print_banner() -> Result<()> {
    // Load the FIGlet font from embedded assets.
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow!("failed to load font: {e}"))?;
    // Convert the app name to FIGlet art.
    let fig = font.convert(APP_NAME).ok_or_else(|| anyhow!("failed to convert text to banner"))?;

    // Print the banner in green.
    println!("{}", console::style(fig).green().bright().bold());
    Ok(())
}
