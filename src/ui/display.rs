use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result};
use bytesize::ByteSize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::{Style, Term};
use figlet_rs::Toilet;
use strum::{Display, EnumString};

use crate::config::APP_NAME;
use crate::file::File;
use crate::types::ProcessorMode;

#[derive(Clone, Copy, Display, EnumString)]
enum Icon {
    #[strum(to_string = "[+]")]
    Ok,
    #[strum(to_string = "[!]")]
    Warn,
    #[strum(to_string = "[E]")]
    Lock,
    #[strum(to_string = "[D]")]
    Unlock,
    #[strum(to_string = "[-]")]
    Trash,
    #[strum(to_string = "[i]")]
    Info,
}

#[derive(Display)]
enum EncryptionStatus {
    #[strum(to_string = "[E] encrypted")]
    Encrypted,
    #[strum(to_string = "[D] unencrypted")]
    Unencrypted,
}

impl From<bool> for EncryptionStatus {
    fn from(encrypted: bool) -> Self {
        if encrypted { Self::Encrypted } else { Self::Unencrypted }
    }
}

impl EncryptionStatus {
    fn color(&self) -> Color {
        match self {
            Self::Encrypted => Color::Cyan,
            Self::Unencrypted => Color::Green,
        }
    }
}

const ICON: Style = Style::new().green().bright();
const TEXT: Style = Style::new().white().bright();
const WARNING: Style = Style::new().yellow().bright();
const BANNER: Style = Style::new().green().bright();

fn base_table() -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS).set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn kv_table(rows: impl IntoIterator<Item = (&'static str, String)>) -> Table {
    let mut table = base_table();
    for (k, v) in rows {
        table.add_row([colored(k, Color::Green), colored(&v, Color::White)]);
    }
    table
}

fn colored(text: &(impl ToString + ?Sized), color: Color) -> Cell {
    Cell::new(text.to_string()).fg(color)
}

fn filename(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or_default()
}

pub struct Display {
    term: Term,
    name_max_len: usize,
}

impl Display {
    pub fn new(name_max_len: usize) -> Self {
        Self { term: Term::stdout(), name_max_len }
    }

    fn print(&self, line: impl std::fmt::Display) -> Result<()> {
        self.term.write_line(&line.to_string()).context("Failed to write to terminal")
    }

    fn blank(&self) -> Result<()> {
        self.term.write_line("").context("Failed to write blank line")
    }

    fn message(&self, icon: Icon, text: impl std::fmt::Display) -> Result<()> {
        self.print(format!("{} {}", ICON.apply_to(icon), TEXT.apply_to(text)))
    }

    fn truncate<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if s.len() > self.name_max_len { format!("{}…", &s[..self.name_max_len.saturating_sub(1)]).into() } else { s.into() }
    }

    pub async fn files(&self, items: &mut [File]) -> Result<()> {
        if items.is_empty() {
            return self.print(WARNING.apply_to("No files found"));
        }

        self.blank()?;
        self.message(Icon::Ok, format!("Found {} file(s):", items.len()))?;
        self.blank()?;

        let mut table = base_table();
        table.set_header(["No", "Name", "Size", "Status"].map(|h| colored(&h, Color::White)));

        for (i, file) in items.iter_mut().enumerate() {
            let name = self.truncate(filename(file.path())).into_owned();
            let size = ByteSize(file.size().await?).to_string();
            let status = EncryptionStatus::from(file.is_encrypted());

            table.add_row([Cell::new(i + 1), colored(&name, Color::Green), Cell::new(size), colored(&status, status.color())]);
        }

        self.print(table)?;
        self.blank()
    }

    pub fn success(&self, mode: ProcessorMode, path: &Path) -> Result<()> {
        let (icon, label) = match mode {
            ProcessorMode::Encrypt => (Icon::Lock, "encrypted"),
            ProcessorMode::Decrypt => (Icon::Unlock, "decrypted"),
        };
        self.blank()?;
        self.message(icon, format!("File {label} successfully: {}", filename(path)))
    }

    pub fn deleted(&self, path: &Path) -> Result<()> {
        self.message(Icon::Trash, format!("Source file deleted: {}", filename(path)))
    }

    pub fn header(&self, name: &str, size: u64, hash: &str) -> Result<()> {
        self.blank()?;
        self.message(Icon::Info, "Header Information:")?;
        self.print(kv_table([("Original Filename", name.to_owned()), ("Original Size", ByteSize(size).to_string()), ("Original Hash", hash.to_owned())]))
    }

    pub fn banner(&self) -> Result<()> {
        let font = Toilet::future().map_err(|e| anyhow::anyhow!("Failed to load font: {e}"))?;
        let figure = font.convert(APP_NAME).context("Failed to render banner")?;
        self.print(BANNER.apply_to(figure))
    }

    pub fn clear(&self) -> Result<()> {
        self.term.clear_screen().context("Failed to clear terminal")
    }
}
