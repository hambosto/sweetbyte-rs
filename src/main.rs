mod allocator;
mod app;
mod cipher;
mod compression;
mod config;
mod encoding;
mod file;
mod header;
mod padding;
mod secret;
mod types;
mod ui;
mod worker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    crate::app::App::init().execute().await
}
