mod progress;
mod prompt;

use std::path::Path;

use anyhow::{Context, Result};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use figlet_rs::FIGfont;

use crate::config::APP_NAME;
use crate::file::File;
use crate::types::ProcessorMode;

pub use progress::Progress;
pub use prompt::Prompt;

fn filename(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len { format!("{}...", &s[..max_len.saturating_sub(3)]) } else { s.to_owned() }
}

fn icon() -> console::StyledObject<&'static str> {
    console::style("✔").green().bright()
}

fn msg(text: impl std::fmt::Display) {
    println!("{} {}", icon(), console::style(text).white().bright());
}

fn table() -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
    t
}

pub async fn files(items: &mut [File]) -> Result<()> {
    if items.is_empty() {
        println!("{}", console::style("No files found").yellow().bright());
        return Ok(());
    }

    println!();
    msg(format!("Found {} file(s):", items.len()));
    println!();

    let header = ["No", "Name", "Size", "Status"].map(|h| Cell::new(h).fg(Color::White));
    let mut t = table();
    t.set_header(header);

    for (i, file) in items.iter_mut().enumerate() {
        let name = truncate(&filename(file.path()), 25);
        let (status, color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };

        t.add_row([Cell::new(i + 1), Cell::new(name).fg(Color::Green), Cell::new(ByteSize(file.size().await?).to_string()), Cell::new(status).fg(color)]);
    }

    println!("{t}\n");
    Ok(())
}

pub fn success(mode: ProcessorMode, path: &Path) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };
    println!();
    msg(format!("File {action} successfully: {}", filename(path)));
}

pub fn deleted(path: &Path) {
    msg(format!("Source file deleted: {}", filename(path)));
}

pub fn clear() -> Result<()> {
    console::Term::stdout().clear_screen().context("clear screen")
}

pub fn header(name: &str, size: u64, hash: &str) {
    println!();
    println!("{} {}", icon(), console::style("Header Information:").bold());

    let mut t = table();
    t.add_row([Cell::new("Original Filename").fg(Color::Green), Cell::new(name).fg(Color::White)]);
    t.add_row([Cell::new("Original Size").fg(Color::Green), Cell::new(ByteSize(size).to_string()).fg(Color::White)]);
    t.add_row([Cell::new("Original Hash").fg(Color::Green), Cell::new(hash).fg(Color::White)]);

    println!("{t}");
}

pub fn banner() -> Result<()> {
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow::anyhow!("load font: {e}"))?;
    let fig = font.convert(APP_NAME).context("render banner")?;
    println!("{}", console::style(fig).green().bright());
    Ok(())
}
