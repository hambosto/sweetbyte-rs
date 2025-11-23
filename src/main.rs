use anyhow::Result;
use clap::Parser;
use sweetbyte::cli::{self, Cli, Commands};
use sweetbyte::interactive;

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
