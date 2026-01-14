fn run() -> anyhow::Result<()> {
    let cli = sweetbyte_rs::cli::parse();
    match cli.command {
        Some(cmd) => sweetbyte_rs::cli::run_command(cmd),
        None => sweetbyte_rs::cli::run_interactive(),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
