use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::validation::{Magic, Version};

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub magic: Magic,
    pub version: Version,
}

impl Parameters {
    pub fn new(magic: u32, version: u16) -> Result<Self> {
        Ok(Self { magic: Magic::try_new(magic)?, version: Version::try_new(version)? })
    }
}
