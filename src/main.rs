pub mod app;
pub mod compression;
pub mod config;
pub mod crypto;
pub mod encoding;
pub mod file;
pub mod header;
pub mod padding;
pub mod processor;
pub mod stream;
pub mod tui;
pub mod types;
pub mod utils;

use anyhow::Result;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    app::run()
}
