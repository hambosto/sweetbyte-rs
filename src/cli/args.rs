use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "sweetbyte")]
#[command(author = "SweetByte")]
#[command(version = "1.0")]
#[command(about = "A secure file encryption tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt a file or directory
    Encrypt {
        /// Input file or directory path
        #[arg(short, long)]
        input: String,

        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<String>,

        /// Password for encryption (optional)
        #[arg(short, long)]
        password: Option<String>,

        /// Delete source file after successful encryption
        #[arg(short, long, default_value_t = false)]
        delete: bool,
    },
    /// Decrypt a file or directory
    Decrypt {
        /// Input file or directory path
        #[arg(short, long)]
        input: String,

        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<String>,

        /// Password for decryption (optional)
        #[arg(short, long)]
        password: Option<String>,

        /// Delete source file after successful decryption
        #[arg(short, long, default_value_t = false)]
        delete: bool,
    },
}
