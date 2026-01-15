use std::path::Path;

use anyhow::{Result, anyhow};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::{Term, style};
use figlet_rs::FIGfont;

use crate::config::APP_NAME;
use crate::types::{FileInfo, ProcessorMode};

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    const UNIT: u64 = 1024;

    if bytes == 0 {
        return "0 B".to_string();
    }

    if bytes < UNIT {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= UNIT as f64 && unit_idx < UNITS.len() - 1 {
        size /= UNIT as f64;
        unit_idx += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_idx])
}

pub fn show_file_info(files: &[FileInfo]) -> Result<()> {
    if files.is_empty() {
        println!("{}", style("No files found").yellow().bold());
        return Ok(());
    }

    println!();
    println!("{} {}", style("✔").green(), style(format!("Found {} file(s):", files.len())).bold());
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new("No").fg(Color::White), Cell::new("Name").fg(Color::White), Cell::new("Size").fg(Color::White), Cell::new("Status").fg(Color::White)]);

    for (i, file) in files.iter().enumerate() {
        let filename = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        let display_name = if filename.len() > 25 { format!("{}...", &filename[..22]) } else { filename.to_string() };
        let (status_text, status_color) = if file.is_encrypted { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };
        table.add_row(vec![Cell::new(i + 1), Cell::new(&display_name).fg(Color::Green), Cell::new(format_bytes(file.size)), Cell::new(status_text).fg(status_color)]);
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

    println!();
    println!("{} {}", style("✔").green(), style(format!("File {} successfully: {}", action, path.display())).bold());
}

pub fn show_source_deleted(path: &Path) {
    println!("{} {}", style("✔").green(), style(format!("Source file deleted: {}", path.display())).bold());
}

pub fn clear_screen() -> Result<()> {
    let term = Term::stdout();
    term.clear_screen().map_err(|e| anyhow!("failed to clear screen: {}", e))
}

pub fn print_banner() {
    let font = FIGfont::from_content(include_str!("../../resources/rectangles.flf")).expect("failed to load font");
    if let Some(fig) = font.convert(APP_NAME) {
        println!("{}", style(fig).green().bold());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }
}
