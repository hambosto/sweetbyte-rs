mod app;
mod cipher;
mod compression;
mod config;
mod encoding;
mod files;
mod header;
mod padding;
mod pipeline;
mod secret;
mod ui;
mod validation;

use anyhow::{Context, Result};
use mimalloc::MiMalloc;

use crate::config::{NAME_MAX_LEN, PASSWORD_LEN};
use crate::files::{Discover, Files};
use crate::pipeline::Processing;
use crate::ui::{Display, Input};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let input = Input::new(PASSWORD_LEN, true);
    let display = Display::new(NAME_MAX_LEN);

    display.clear()?;
    display.banner()?;

    let processing = input.processing_mode()?;
    let files: Vec<Files> = Discover::new(".", processing).run().into_iter().map(Files::new).collect();
    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    display.files(&files).await?;

    let source = Files::new(input.file(&files)?);
    let target = Files::new(source.output_path(processing));

    if target.exists() && !input.overwrite(&target)? {
        anyhow::bail!("operation canceled");
    }

    let secret = input.password(processing)?;
    let header = match processing {
        Processing::Encryption => app::encrypt(&source, &target, &secret).await?,
        Processing::Decryption => app::decrypt(&source, &target, &secret).await?,
    };

    display.success(processing, &target)?;
    display.header(&header.name, header.size, &hex::encode(&header.hash))?;

    if input.delete(&source, processing)? {
        source.delete().await.context("failed to delete source file")?;
        display.deleted(&source)?;
    }

    display.exit()
}
