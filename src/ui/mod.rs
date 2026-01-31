use std::path::Path;

use anyhow::{Context, Result};
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

pub async fn show_file_info(files: &mut [File]) -> Result<()> {
    if files.is_empty() {
        println!("{}", console::style("No files found").yellow().bright());
        return Ok(());
    }

    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Found {} file(s):", files.len())).white().bright());
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("No").fg(Color::White), Cell::new("Name").fg(Color::White), Cell::new("Size").fg(Color::White), Cell::new("Status").fg(Color::White)]);

    for (i, file) in files.iter_mut().enumerate() {
        let filename = file.path().file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        let display_name = if filename.len() > 25 { format!("{}...", &filename[..22]) } else { filename.to_owned() };
        let (status_text, status_color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };
        let size = file.size().await?;

        table.add_row(vec![Cell::new(i + 1), Cell::new(&display_name).fg(Color::Green), Cell::new(ByteSize(size).to_string()), Cell::new(status_text).fg(status_color)]);
    }

    println!("{table}");
    println!();

    Ok(())
}

pub fn show_success(mode: ProcessorMode, path: &Path) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style(format!("File {action} successfully: {filename}")).white().bright());
}

pub fn show_source_deleted(path: &Path) {
    let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_else(|| path.display().to_string().into());

    println!("{} {}", console::style("✔").green().bright(), console::style(format!("Source file deleted: {filename}")).white().bright());
}

pub fn clear_screen() -> Result<()> {
    Term::stdout().clear_screen().context("clear screen")?;

    Ok(())
}

pub fn show_header_info(filename: &str, size: u64, hash: &str) {
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style("Header Information:").bold());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
    table.add_row(vec![Cell::new("Original Filename").fg(Color::Green), Cell::new(filename).fg(Color::White)]);
    table.add_row(vec![Cell::new("Original Size").fg(Color::Green), Cell::new(ByteSize(size).to_string()).fg(Color::White)]);
    table.add_row(vec![Cell::new("Original Hash").fg(Color::Green), Cell::new(hash).fg(Color::White)]);

    print!("{table}");
}

pub fn print_banner() -> Result<()> {
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|error| anyhow::anyhow!("load font: {error}"))?;
    let fig = font.convert(APP_NAME).context("render banner")?;
    println!("{}", console::style(fig).green().bright());
    Ok(())
}
