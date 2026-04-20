use std::path::Path;

use anyhow::{Context, Result};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::{Style, Term};
use figlet_rs::Toilet;

use crate::config::APP_NAME;
use crate::file::File;
use crate::types::ProcessorMode;

pub struct Display {
    term: Term,
    name_max_len: usize,
}

impl Display {
    #[must_use]
    pub fn new(name_max_len: usize) -> Self {
        Self { term: Term::stdout(), name_max_len }
    }

    fn print(&self, s: impl Into<String>) -> Result<()> {
        self.term.write_line(&s.into()).context("write failed")
    }

    fn message(&self, icon: &str, text: impl std::fmt::Display) -> Result<()> {
        let line = format!("{} {}", Style::new().green().bright().apply_to(icon), Style::new().white().bright().apply_to(text));
        self.print(line)
    }

    pub async fn files(&self, items: &mut [File]) -> Result<()> {
        if items.is_empty() {
            return self.print(Style::new().yellow().bright().apply_to("No files found").to_string());
        }

        self.print("")?;
        self.message("[+]", format!("Found {} file(s):", items.len()))?;
        self.print("")?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(["No", "Name", "Size", "Status"].map(|h| Cell::new(h).fg(Color::White)));

        for (i, file) in items.iter_mut().enumerate() {
            let raw_name = file.path().file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let name = if raw_name.len() > self.name_max_len { &raw_name[..self.name_max_len.saturating_sub(1)] } else { raw_name };
            let size = ByteSize(file.size().await?).to_string();
            let (status, color) = if file.is_encrypted() { ("[E] encrypted", Color::Cyan) } else { ("[D] unencrypted", Color::Green) };
            table.add_row([Cell::new(i + 1), Cell::new(name).fg(Color::Green), Cell::new(size), Cell::new(status).fg(color)]);
        }

        self.print(table.to_string())?;
        self.print("")
    }

    pub fn success(&self, mode: ProcessorMode, path: &Path) -> Result<()> {
        let (icon, verb) = match mode {
            ProcessorMode::Encrypt => ("[E]", "encrypted"),
            ProcessorMode::Decrypt => ("[D]", "decrypted"),
        };
        self.print("")?;
        self.message(icon, format!("File {verb} successfully: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or_default()))
    }

    pub fn deleted(&self, path: &Path) -> Result<()> {
        self.message("[-]", format!("Source file deleted: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or_default()))
    }

    pub fn header(&self, name: &str, size: u64, hash: &str) -> Result<()> {
        self.print("")?;
        self.message("[i]", "Header Information:")?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);

        let size_str = ByteSize(size).to_string();
        for (k, v) in [("Original Filename", name), ("Original Size", &size_str), ("Original Hash", hash)] {
            table.add_row([Cell::new(k).fg(Color::Green), Cell::new(v).fg(Color::White)]);
        }

        self.print(table.to_string())
    }

    pub fn banner(&self) -> Result<()> {
        let toilet = Toilet::future().map_err(|e| anyhow::anyhow!("font: {e}"))?;
        let figure = toilet.convert(APP_NAME).context("render failed")?;
        self.print(Style::new().green().bright().apply_to(figure).to_string())
    }

    pub fn clear(&self) -> Result<()> {
        self.term.clear_screen().context("clear failed")
    }
}
