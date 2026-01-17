use std::process;
use sweetbyte_rs::cli::Cli;

fn main() {
    if let Err(e) = Cli::init().execute() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
