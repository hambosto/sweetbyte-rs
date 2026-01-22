use std::path::Path;

use anyhow::{Result, anyhow};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::Term;
use figlet_rs::FIGfont;

use crate::config::{ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, APP_NAME, COMPRESSION_ZLIB, ENCODING_REED_SOLOMON, KDF_ARGON2};
use crate::file::File;
use crate::header::Header;
use crate::types::ProcessorMode;

pub mod progress;
pub mod prompt;

pub fn show_header_info(header: &Header) -> Result<()> {
    println!();
    println!("{} {}", console::style("✔").green().bright(), console::style("File Header Information:").white().bright());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("Field").fg(Color::White), Cell::new("Value").fg(Color::White)]);

    let metadata = header.metadata();
    if let Some(m) = metadata {
        table.add_row(vec![Cell::new("Filename").fg(Color::Green), Cell::new(m.filename()).fg(Color::White)]);
        table.add_row(vec![Cell::new("File Size").fg(Color::Green), Cell::new(ByteSize(m.size()).to_string()).fg(Color::White)]);
        table.add_row(vec![Cell::new("Created At").fg(Color::Green), Cell::new(format_timestamp(m.created_at())).fg(Color::White)]);
        table.add_row(vec![Cell::new("Modified At").fg(Color::Green), Cell::new(format_timestamp(m.modified_at())).fg(Color::White)]);
    }

    table.add_row(vec![Cell::new("Algorithm").fg(Color::Cyan), Cell::new(format_algorithm(header.algorithm())).fg(Color::White)]);
    table.add_row(vec![Cell::new("Compression").fg(Color::Cyan), Cell::new(format_compression(header.compression())).fg(Color::White)]);
    table.add_row(vec![Cell::new("Encoding").fg(Color::Cyan), Cell::new(format_encoding(header.encoding())).fg(Color::White)]);
    table.add_row(vec![Cell::new("KDF").fg(Color::Cyan), Cell::new(format_kdf(header.kdf())).fg(Color::White)]);

    if let Some(hash) = header.content_hash() {
        table.add_row(vec![Cell::new("Content Hash").fg(Color::Magenta), Cell::new(hex::encode(hash)).fg(Color::White)]);
    }

    println!("{table}");
    println!();
    Ok(())
}

pub fn show_file_info(files: &mut [File]) -> Result<()> {
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

        let size = file.size()?;

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
    let term = Term::stdout();
    term.clear_screen().map_err(|e| anyhow!("failed to clear screen: {e}"))?;
    Ok(())
}

pub fn print_banner() -> Result<()> {
    let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow!("failed to load font: {e}"))?;

    let fig = font.convert(APP_NAME).ok_or_else(|| anyhow!("failed to convert text to banner"))?;

    println!("{}", console::style(fig).green().bright());
    Ok(())
}

fn format_algorithm(alg: u8) -> String {
    match alg {
        x if x == ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305 => "AES-256-GCM + ChaCha20-Poly1305".to_owned(),
        ALGORITHM_AES_256_GCM => "AES-256-GCM".to_owned(),
        ALGORITHM_CHACHA20_POLY1305 => "ChaCha20-Poly1305".to_owned(),
        _ => format!("Unknown ({alg:#04x})"),
    }
}

fn format_compression(comp: u8) -> String {
    match comp {
        COMPRESSION_ZLIB => "Zlib".to_owned(),
        _ => format!("Unknown ({comp:#04x})"),
    }
}

fn format_encoding(enc: u8) -> String {
    match enc {
        ENCODING_REED_SOLOMON => "Reed-Solomon".to_owned(),
        _ => format!("Unknown ({enc:#04x})"),
    }
}

fn format_kdf(kdf: u8) -> String {
    match kdf {
        KDF_ARGON2 => "Argon2".to_owned(),
        _ => format!("Unknown ({kdf:#04x})"),
    }
}

fn format_timestamp(ts: u64) -> String {
    match ts {
        0 => "N/A".to_owned(),
        _ => {
            let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(ts as i64, 0);
            match datetime {
                Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                None => format!("Invalid timestamp ({ts})"),
            }
        }
    }
}
