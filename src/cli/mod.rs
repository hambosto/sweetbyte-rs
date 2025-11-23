pub mod args;
pub mod commands;

pub use args::{Cli, Commands};
pub use commands::{handle_decrypt, handle_encrypt};
