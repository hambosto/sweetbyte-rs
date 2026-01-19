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

use std::process;

use cli::Cli;

fn main() {
    if let Err(e) = Cli::init().execute() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
