pub mod cli;
pub mod compression;
pub mod config;
pub mod crypto;
pub mod encoding;
pub mod file;
pub mod header;
pub mod interactive;
pub mod padding;
pub mod processor;
pub mod stream;
pub mod tui;
pub mod types;
pub mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encrypt {
            input,
            output,
            password,
            delete,
        }) => {
            cli::handle_encrypt(&input, output, password, delete)?;
        }
        Some(Commands::Decrypt {
            input,
            output,
            password,
            delete,
        }) => {
            cli::handle_decrypt(&input, output, password, delete)?;
        }
        None => {
            // No args provided, run interactive mode
            interactive::run()?;
        }
    }

    Ok(())
}
