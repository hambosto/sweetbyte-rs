//! Display utilities for file information.

use anyhow::Result;
use console::{Term, style};

use crate::types::{FileInfo, ProcessorMode};

/// Formats bytes into human-readable string.
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

/// Displays file information in a table.
///
/// # Arguments
/// * `files` - List of file info
pub fn show_file_info(files: &[FileInfo]) -> Result<()> {
    if files.is_empty() {
        println!("{}", style("No files found").yellow());
        return Ok(());
    }

    println!();
    println!(
        "{} {}",
        style("✓").green(),
        style(format!("Found {} file(s):", files.len())).bold()
    );
    println!();

    // Print header
    println!(
        "  {:>4}  {:28}  {:>10}  {:12}",
        style("No").bold(),
        style("Name").bold(),
        style("Size").bold(),
        style("Status").bold()
    );
    println!("  {}", "-".repeat(60));

    // Print files
    for (i, file) in files.iter().enumerate() {
        let filename = file
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let display_name = if filename.len() > 25 {
            format!("{}...", &filename[..22])
        } else {
            filename.to_string()
        };

        let status = if file.is_encrypted {
            style("encrypted").cyan()
        } else {
            style("unencrypted").green()
        };

        println!(
            "  {:>4}  {:28}  {:>10}  {}",
            style(i + 1).bold(),
            style(&display_name).green(),
            format_bytes(file.size),
            status
        );
    }

    println!();
    Ok(())
}

/// Displays success message.
///
/// # Arguments
/// * `mode` - The processing mode
/// * `path` - The output path
pub fn show_success(mode: ProcessorMode, path: &std::path::Path) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    println!();
    println!(
        "{} {}",
        style("✓").green(),
        style(format!("File {} successfully: {}", action, path.display())).bold()
    );
}

/// Displays source deleted message.
///
/// # Arguments
/// * `path` - The deleted file path
pub fn show_source_deleted(path: &std::path::Path) {
    println!(
        "{} {}",
        style("✓").green(),
        style(format!("Source file deleted: {}", path.display())).bold()
    );
}

/// Clears the terminal screen.
pub fn clear_screen() -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()
        .map_err(|e| anyhow::anyhow!("failed to clear screen: {}", e))
}

/// Prints the application banner.
pub fn print_banner() {
    let banner = r#"
   _____                     __  __          __
  / ___/  _____  ___  / /_/ /_ __  __/ /____
  \__ \ | /| / / _ \/ _ \/ __/ __ \/ / / / __/ _ \
 ___/ / |/ |/ /  __/  __/ /_/ /_/ / /_/ / /_/  __/
/____/|__/|__/\___/\___/\__/_.___/\__, /\__/\___/
                                 /____/
"#;

    println!("{}", style(banner).green().bold());
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
