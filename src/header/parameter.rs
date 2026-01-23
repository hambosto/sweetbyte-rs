use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::HEADER_DATA_SIZE;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HeaderParameter {
    pub version: u16,
    pub algorithm: u8,
    pub compression: u8,
    pub encoding: u8,
    pub kdf: u8,
    pub kdf_memory: u32,
    pub kdf_time: u8,
    pub kdf_parallelism: u8,
}

impl HeaderParameter {
    pub fn serialize(&self) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];

        data[0..2].copy_from_slice(&self.version.to_be_bytes());
        data[2] = self.algorithm;
        data[3] = self.compression;
        data[4] = self.encoding;
        data[5] = self.kdf;
        data[6..10].copy_from_slice(&self.kdf_memory.to_be_bytes());
        data[10] = self.kdf_time;
        data[11] = self.kdf_parallelism;

        data
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);
        let algorithm = data[2];
        let compression = data[3];
        let encoding = data[4];
        let kdf = data[5];
        let kdf_memory = u32::from_be_bytes(data[6..10].try_into().context("kdf memory conversion")?);
        let kdf_time = data[10];
        let kdf_parallelism = data[11];

        Ok(Self { version, algorithm, compression, encoding, kdf, kdf_memory, kdf_time, kdf_parallelism })
    }
}
