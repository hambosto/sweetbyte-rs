use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[nutype::nutype(
    validate(predicate = |&m| m == MAGIC_BYTES),
    derive(Debug, Clone, Copy, AsRef, Serialize, Deserialize)
)]
pub struct Magic(u32);

#[nutype::nutype(
    validate(predicate = |&v| v == CURRENT_VERSION),
    derive(Debug, Clone, Copy, AsRef, Serialize, Deserialize)
)]
pub struct Version(u16);

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
