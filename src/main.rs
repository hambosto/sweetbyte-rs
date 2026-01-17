pub mod cipher;
pub mod cli;
pub mod compression;
pub mod config;
pub mod encoding;
pub mod file;
pub mod header;
pub mod padding;
pub mod processor;
pub mod stream;
pub mod types;
pub mod ui;

use std::process;

use cli::Cli;

fn main() {
    if let Err(e) = Cli::init().execute() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
