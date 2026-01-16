use std::process;

use anyhow::Result;
use sweetbyte_rs::cli::Cli;

fn run() -> Result<()> {
    Cli::init().execute()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
