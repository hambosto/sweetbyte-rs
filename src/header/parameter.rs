use wincode::{SchemaRead, SchemaWrite};

use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[derive(SchemaRead, SchemaWrite)]
pub struct Parameters {
    pub magic: u32,
    pub version: u16,
}

impl Parameters {
    pub fn validate(&self) -> bool {
        if self.magic != MAGIC_BYTES {
            tracing::error!("invalid magic: {:08X}", self.magic);
            return false;
        }

        if self.version != CURRENT_VERSION {
            tracing::error!("invalid version: {}", self.version);
            return false;
        }

        true
    }
}
