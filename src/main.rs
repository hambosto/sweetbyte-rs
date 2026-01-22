mod cipher;
mod cli;
mod compression;
mod config;
mod encoding;
mod file;
mod header;
mod padding;
mod processor;
mod types;
mod ui;
mod worker;

use anyhow::Result;
use cli::Cli;

fn main() -> Result<()> {
    Cli::init().execute()
}
