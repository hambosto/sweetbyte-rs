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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // dank its ugly. damn.
    crate::cli::Cli::init().execute().await
}
