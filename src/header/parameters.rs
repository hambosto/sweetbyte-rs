use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub magic: u32,
    pub version: u16,
}

impl Parameters {
    pub fn new(magic: u32, version: u16) -> Result<Self> {
        if magic != MAGIC_BYTES {
            anyhow::bail!("invalid magic bytes: expected {MAGIC_BYTES:#x}, found {magic:#x}");
        }
        if version != CURRENT_VERSION {
            anyhow::bail!("unsupported version: expected {CURRENT_VERSION}, found {version}");
        }

        Ok(Self { magic, version })
    }
}
