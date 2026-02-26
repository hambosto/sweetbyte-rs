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

pub struct Display {
    name_max_len: usize,
    icon: &'static str,
}

impl Display {
    pub fn new(name_max_len: usize, icon: &'static str) -> Self {
        Self { name_max_len, icon }
    }

    fn filename(path: &Path) -> String {
        path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
    }

    fn truncate(&self, s: &str) -> String {
        if s.len() > self.name_max_len { format!("{}...", &s[..self.name_max_len.saturating_sub(3)]) } else { s.to_owned() }
    }

    fn icon(&self) -> console::StyledObject<&'static str> {
        console::style(self.icon).green().bright()
    }

    fn msg(&self, text: impl std::fmt::Display) {
        println!("{} {}", self.icon(), console::style(text).white().bright());
    }

    fn table() -> Table {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
        table
    }

    fn action_label(mode: ProcessorMode) -> &'static str {
        match mode {
            ProcessorMode::Encrypt => "encrypted",
            ProcessorMode::Decrypt => "decrypted",
        }
    }

    pub async fn files(&self, items: &mut [File]) -> Result<()> {
        if items.is_empty() {
            println!("{}", console::style("No files found").yellow().bright());
            return Ok(());
        }

        println!();
        self.msg(format!("Found {} file(s):", items.len()));
        println!();

        let header = ["No", "Name", "Size", "Status"].map(|h| Cell::new(h).fg(Color::White));
        let mut table = Self::table();
        table.set_header(header);

        for (i, file) in items.iter_mut().enumerate() {
            let name = self.truncate(&Self::filename(file.path()));
            let (status, color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };

            table.add_row([Cell::new(i + 1), Cell::new(name).fg(Color::Green), Cell::new(ByteSize(file.size().await?).to_string()), Cell::new(status).fg(color)]);
        }

        println!("{table}");
        println!("\n");
        Ok(())
    }

    pub fn success(&self, mode: ProcessorMode, path: &Path) {
        println!();
        self.msg(format!("File {} successfully: {}", Self::action_label(mode), Self::filename(path)));
    }

    pub fn deleted(&self, path: &Path) {
        self.msg(format!("Source file deleted: {}", Self::filename(path)));
    }

    pub fn clear() -> Result<()> {
        console::Term::stdout().clear_screen().context("clear screen")
    }

    pub fn header(&self, name: &str, size: u64, hash: &str) {
        println!();
        println!("{} {}", self.icon(), console::style("Header Information:").bold());

        let mut table = Self::table();
        table.add_row([Cell::new("Original Filename").fg(Color::Green), Cell::new(name).fg(Color::White)]);
        table.add_row([Cell::new("Original Size").fg(Color::Green), Cell::new(ByteSize(size).to_string()).fg(Color::White)]);
        table.add_row([Cell::new("Original Hash").fg(Color::Green), Cell::new(hash).fg(Color::White)]);

        println!("{table}");
    }

    pub fn banner() -> Result<()> {
        let font = FIGfont::from_content(include_str!("../../assets/rectangles.flf")).map_err(|e| anyhow::anyhow!("load font: {e}"))?;
        let fig = font.convert(APP_NAME).context("render banner")?;
        println!("{}", console::style(fig).green().bright());
        Ok(())
    }
}

impl Default for Display {
    fn default() -> Self {
        Self::new(25, "✔")
    }
}
