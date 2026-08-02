use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{Magic, Version};

#[derive(Serialize, Deserialize)]
pub(crate) struct Parameters {
    pub(crate) magic: Magic,
    pub(crate) version: Version,
}

impl Parameters {
    pub(crate) fn new(magic: u32, version: u16) -> Result<Self> {
        let magic = Magic::try_new(magic).context("invalid magic bytes")?;
        let version = Version::try_new(version).context("invalid version")?;

        Ok(Self { magic, version })
    }
}
