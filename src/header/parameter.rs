use anyhow::Result;
use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, COMPRESSION_ZLIB, CURRENT_VERSION, ENCODING_REED_SOLOMON, KDF_ARGON2};

#[derive(Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct Parameters {
    pub kdf_memory: u32,
    pub version: u16,
    pub algorithm: u8,
    pub compression: u8,
    pub encoding: u8,
    pub kdf: u8,
    pub kdf_time: u8,
    pub kdf_parallelism: u8,
}

impl Parameters {
    pub fn validate(&self) -> Result<()> {
        if self.version != CURRENT_VERSION {
            anyhow::bail!("unsupported version: {}", self.version);
        }

        if self.algorithm != (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305) {
            anyhow::bail!("unsupported algorithm: {}", self.algorithm);
        }

        if self.compression != COMPRESSION_ZLIB {
            anyhow::bail!("unsupported compression: {}", self.compression);
        }

        if self.encoding != ENCODING_REED_SOLOMON {
            anyhow::bail!("unsupported encoding: {}", self.encoding);
        }

        if self.kdf != KDF_ARGON2 {
            anyhow::bail!("unsupported kdf: {}", self.kdf);
        }

        Ok(())
    }
}
