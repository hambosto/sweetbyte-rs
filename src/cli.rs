use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    Interactive,
}

impl Cli {
    #[must_use] 
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
