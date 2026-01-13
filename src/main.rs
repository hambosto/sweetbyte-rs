//! SweetByte - Multi-layered file encryption with error correction.

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = sweetbyte_rs::cli::parse();

    match cli.command {
        Some(cmd) => sweetbyte_rs::cli::run_command(cmd),
        None => sweetbyte_rs::interactive::run(),
    }
}
