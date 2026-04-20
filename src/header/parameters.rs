use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[derive(Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub magic: u32,
    pub version: u16,
}

impl Parameters {
    pub fn new(magic: u32, version: u16) -> Result<Self> {
        anyhow::ensure!(magic == MAGIC_BYTES, "Invalid magic: {magic:08X}");
        anyhow::ensure!(version == CURRENT_VERSION, "Invalid version: {version:04X}");

        Ok(Self { magic, version })
    }
}
