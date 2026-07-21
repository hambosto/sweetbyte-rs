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

use crate::config::PASSWORD_LEN;
use crate::files::{Discover, Files};
use crate::pipeline::Operation;
use crate::ui::Input;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let input = Input::new(PASSWORD_LEN, true);

    crate::ui::display::clear()?;
    crate::ui::display::banner()?;

    let operation = input.operation_mode()?;
    let files: Vec<Files> = Discover::new(".", operation).run().into_iter().map(Files::new).collect();
    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    crate::ui::display::files(&files).await?;

    let source = Files::new(input.file(&files)?);
    let target = Files::new(source.output_path(operation));

    if target.exists() && !input.overwrite(&target)? {
        anyhow::bail!("operation canceled");
    }

    let secret = input.password(operation)?;
    let header = match operation {
        Operation::Encryption => app::encrypt(&source, &target, &secret).await?,
        Operation::Decryption => app::decrypt(&source, &target, &secret).await?,
    };

    crate::ui::display::success(operation, &target)?;
    crate::ui::display::header(&header.name, header.size, &hex::encode(&header.hash))?;

    if input.delete(&source, operation)? {
        source.delete().await.context("failed to delete source file")?;
        crate::ui::display::deleted(&source)?;
    }

    crate::ui::display::exit()
}
