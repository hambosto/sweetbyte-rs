use std::path::Path;

use anyhow::{Context, Result};
// use cliclack::{clear_screen, log, note, outro};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use humansize::DECIMAL;

use crate::config::APP_NAME;
use crate::files::Files;
use crate::types::{PathName, Processing};

pub struct Display {
    name_len: usize,
}

impl Display {
    pub fn new(name_len: usize) -> Self {
        Self { name_len }
    }

    pub async fn files(&self, items: &mut [Files]) -> Result<()> {
        if items.is_empty() {
            return cliclack::log::warning("No files found").context("warning failed");
        }

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(["No", "Name", "Size", "Status"].map(|h| Cell::new(h).fg(Color::White)));

        for (i, file) in items.iter_mut().enumerate() {
            let file_name = if file.path().name().len() > self.name_len {
                &file.path().name()[..self.name_len.saturating_sub(1)]
            } else {
                file.path().name()
            };

            let file_size = humansize::format_size(file.size().await?, DECIMAL);
            let file_status = if file.is_encrypted() { "[E] encrypted" } else { "[D] unencrypted" };
            let status_color = if file.is_encrypted() { Color::Cyan } else { Color::Green };

            table.add_row([Cell::new(i + 1).fg(Color::Green), Cell::new(file_name).fg(Color::Green), Cell::new(file_size).fg(Color::Green), Cell::new(file_status).fg(status_color)]);
        }

        cliclack::note(format!("Found {} file(s)", items.len()), table.to_string()).context("note failed")
    }

    pub fn success(&self, processing: Processing, file_path: &Path) -> Result<()> {
        let verb = match processing {
            Processing::Encryption => "encrypted",
            Processing::Decryption => "decrypted",
        };

        cliclack::log::success(format!("File {verb} successfully: {}", file_path.name())).context("log failed")
    }

    pub fn deleted(&self, file_path: &Path) -> Result<()> {
        cliclack::log::success(format!("Source file deleted: {}", file_path.name())).context("log failed")
    }

    pub fn header(&self, file_name: &str, file_size: u64, file_hash: &str) -> Result<()> {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);

        let file_size = humansize::format_size(file_size, DECIMAL);
        table.add_row([Cell::new("Original Filename").fg(Color::Green), Cell::new(file_name).fg(Color::White)]);
        table.add_row([Cell::new("Original Size").fg(Color::Green), Cell::new(&file_size).fg(Color::White)]);
        table.add_row([Cell::new("Original Hash").fg(Color::Green), Cell::new(file_hash).fg(Color::White)]);

        cliclack::note("Header Information", table.to_string()).context("note failed")
    }

    pub fn banner(&self) -> Result<()> {
        cliclack::intro(APP_NAME).context("intro failed")
    }

    pub fn exit(&self) -> Result<()> {
        cliclack::outro("Exiting").context("outro failed")
    }

    pub fn clear(&self) -> Result<()> {
        cliclack::clear_screen().context("clear failed")
    }
}
