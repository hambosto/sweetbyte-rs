use std::path::Path;

use anyhow::{Context, Result};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::StyledObject;
use figlet_rs::FIGlet;

use crate::config::APP_NAME;
use crate::file::File;
use crate::types::ProcessorMode;

pub struct Display {
    name_max_len: usize,
    icon: &'static str,
}

impl Default for Display {
    fn default() -> Self {
        Self::new(25, "✔")
    }
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

    fn icon(&self) -> StyledObject<&'static str> {
        console::style(self.icon).green().bright()
    }

    fn msg(&self, text: impl std::fmt::Display) {
        println!("{} {}", self.icon(), console::style(text).white().bright());
    }

    fn table() -> Table {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
        t
    }

    fn colored<S: ToString + ?Sized>(text: &S, color: Color) -> Cell {
        Cell::new(text.to_string()).fg(color)
    }

    pub async fn files(&self, items: &mut [File]) -> Result<()> {
        if items.is_empty() {
            println!("{}", console::style("No files found").yellow().bright());
            return Ok(());
        }

        println!();
        self.msg(format!("Found {} file(s):", items.len()));
        println!();

        let mut table = Self::table();
        table.set_header(["No", "Name", "Size", "Status"].map(|h| Self::colored(h, Color::White)));

        for (i, file) in items.iter_mut().enumerate() {
            let (status, status_color) = if file.is_encrypted() { ("encrypted", Color::Cyan) } else { ("unencrypted", Color::Green) };

            table.add_row([
                Cell::new(i + 1),
                Self::colored(&self.truncate(&Self::filename(file.path())), Color::Green),
                Cell::new(ByteSize(file.size().await?).to_string()),
                Self::colored(status, status_color),
            ]);
        }

        println!("{table}\n");

        Ok(())
    }

    pub fn success(&self, mode: ProcessorMode, path: &Path) {
        let label = match mode {
            ProcessorMode::Encrypt => "encrypted",
            ProcessorMode::Decrypt => "decrypted",
        };
        println!();
        self.msg(format!("File {label} successfully: {}", Self::filename(path)));
    }

    pub fn deleted(&self, path: &Path) {
        self.msg(format!("Source file deleted: {}", Self::filename(path)));
    }

    pub fn header(&self, name: &str, size: u64, hash: &str) {
        println!();
        println!("{} {}", self.icon(), console::style("Header Information:").bold());

        let mut table = Self::table();
        for (label, value) in [("Original Filename", name.to_owned()), ("Original Size", ByteSize(size).to_string()), ("Original Hash", hash.to_owned())] {
            table.add_row([Self::colored(label, Color::Green), Self::colored(&value, Color::White)]);
        }

        println!("{table}");
    }

    pub fn banner() -> Result<()> {
        let figlet_font = FIGlet::from_file("assets/rectangles.flf").map_err(|e| anyhow::anyhow!("Failed to load font: {e}"))?;
        let figure = figlet_font.convert(APP_NAME).context("Failed to render banner")?;
        println!("{}", console::style(figure).green().bright());
        Ok(())
    }

    pub fn clear() -> Result<()> {
        console::Term::stdout().clear_screen().context("Failed to clear terminal")
    }
}
