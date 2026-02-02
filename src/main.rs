mod allocator;
mod app;
mod cipher;
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

use crate::app::App;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    App::init()?.execute().await
}
