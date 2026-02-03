use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, COMPRESSION_ZSTD, CURRENT_VERSION, ENCODING_REED_SOLOMON, KDF_ARGON2};

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
    pub fn validate(&self) -> bool {
        if self.version != CURRENT_VERSION {
            tracing::error!("invalid version: {}", self.version);
            return false;
        }

        if self.algorithm != (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305) {
            tracing::error!("invalid algorithm: {}", self.algorithm);
            return false;
        }

        if self.compression != COMPRESSION_ZSTD {
            tracing::error!("invalid compression: {}", self.compression);
            return false;
        }

        if self.encoding != ENCODING_REED_SOLOMON {
            tracing::error!("invalid encoding: {}", self.encoding);
            return false;
        }

        if self.kdf != KDF_ARGON2 {
            tracing::error!("invalid kdf: {}", self.kdf);
            return false;
        }

        true
    }
}
