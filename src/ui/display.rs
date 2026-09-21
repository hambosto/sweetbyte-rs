use anyhow::{Context, Result};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};

use crate::core::Operation;
use crate::fs::FileHandle;

pub(crate) async fn list_files(items: &[FileHandle]) -> Result<()> {
    if items.is_empty() {
        return cliclack::log::warning("No files found").context("failed to display files");
    }

    let mut table = Table::new();
    table.load_style(UTF8_FULL.with_rounded_corners()).set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(["No", "Name", "Size", "Status"].map(|h| Cell::new(h).fg(Color::White)));

    for (index, file) in items.iter().enumerate() {
        let size = file.size().await.context("failed to read file size")?;
        let formatted = humansize::format_size(size, humansize::DECIMAL);
        let file_status = if file.is_encrypted() { "[E] encrypted" } else { "[D] unencrypted" };
        let status_color = if file.is_encrypted() { Color::Cyan } else { Color::Green };

        table.add_row([Cell::new(index.saturating_add(1)).fg(Color::Green), Cell::new(file.name()).fg(Color::Green), Cell::new(formatted).fg(Color::Green), Cell::new(file_status).fg(status_color)]);
    }

    cliclack::note(format!("Found {} file(s)", items.len()), table).context("failed to display files")
}

pub(crate) fn show_success(operation: Operation, file: &FileHandle) -> Result<()> {
    let action = match operation {
        Operation::Encryption => "encrypted",
        Operation::Decryption => "decrypted",
    };

    cliclack::log::success(format!("File {action}: {}", file.name())).context("failed to display success")
}

pub(crate) fn show_deletion(file: &FileHandle) -> Result<()> {
    cliclack::log::success(format!("File deleted: {}", file.name())).context("failed to display deletion")
}

pub(crate) fn show_header(file_name: &str, file_size: u64, file_hash: &[u8]) -> Result<()> {
    let mut table = Table::new();
    table.load_style(UTF8_FULL.with_rounded_corners()).set_content_arrangement(ContentArrangement::Dynamic);

    table.add_row([Cell::new("Original Filename").fg(Color::Green), Cell::new(file_name).fg(Color::White)]);
    table.add_row([Cell::new("Original Size").fg(Color::Green), Cell::new(humansize::format_size(file_size, humansize::DECIMAL)).fg(Color::White)]);
    table.add_row([Cell::new("Original Hash").fg(Color::Green), Cell::new(hex::encode(file_hash)).fg(Color::White)]);

    cliclack::note("Header Information", table).context("failed to display header")
}

pub(crate) fn show_banner() -> Result<()> {
    let app_name = env!("CARGO_PKG_NAME");
    let version = option_env!("SWEETBYTE_BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));

    cliclack::intro(format!("{app_name} {version}")).context("failed to display banner")
}

pub(crate) fn show_exit() -> Result<()> {
    cliclack::outro("Exiting").context("failed to display exit")
}

pub(crate) fn clear_screen() -> Result<()> {
    cliclack::clear_screen().context("failed to clear screen")
}
