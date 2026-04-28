pub mod config;
pub mod core;
pub mod files;
pub mod header;
pub mod secret;
pub mod types;
pub mod ui;
pub mod worker;

pub(crate) mod compression;
pub(crate) mod encoding;
pub(crate) mod padding;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
