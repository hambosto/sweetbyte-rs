use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::validation::{Magic, Version};

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub magic: Magic,
    pub version: Version,
}

impl Parameters {
    pub fn new(magic: u32, version: u16) -> Result<Self> {
        let magic = Magic::try_new(magic).context("invalid magic bytes")?;
        let version = Version::try_new(version).context("invalid version")?;

        Ok(Self { magic, version })
    }
}
