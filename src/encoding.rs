use anyhow::Result;
use hashbrown::HashMap;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

const HEADER_BYTES: usize = 4;
const CRC_BYTES: usize = 4;

pub struct Encoding {
    data_shards: usize,
    parity_shards: usize,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if !ReedSolomonEncoder::supports(data_shards, parity_shards) {
            anyhow::bail!("unsupported configuration: {data_shards} original + {parity_shards} recovery shards");
        }

        Ok(Self { data_shards, parity_shards })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_bytes = data.len().div_ceil(self.data_shards).next_multiple_of(2);
        let chunk_bytes = CRC_BYTES + shard_bytes;
        let total_shards = self.data_shards + self.parity_shards;

        let mut result = vec![0u8; HEADER_BYTES + chunk_bytes * total_shards];
        result[..HEADER_BYTES].copy_from_slice(&u32::try_from(data.len())?.to_le_bytes());

        let mut encoder = ReedSolomonEncoder::new(self.data_shards, self.parity_shards, shard_bytes)?;

        for shard_idx in 0..self.data_shards {
            let chunk_offset = HEADER_BYTES + shard_idx * chunk_bytes;
            let shard_offset = chunk_offset + CRC_BYTES;
            let chunk_end = chunk_offset + chunk_bytes;

            let data_slice = &data[shard_idx * shard_bytes..((shard_idx + 1) * shard_bytes).min(data.len())];
            result[shard_offset..shard_offset + data_slice.len()].copy_from_slice(data_slice);

            let crc = crc32fast::hash(&result[shard_offset..chunk_end]).to_le_bytes();
            result[chunk_offset..shard_offset].copy_from_slice(&crc);

            encoder.add_original_shard(&result[shard_offset..chunk_end])?;
        }

        for (parity_idx, parity_shard) in encoder.encode()?.recovery_iter().enumerate() {
            let chunk_offset = HEADER_BYTES + (self.data_shards + parity_idx) * chunk_bytes;
            let shard_offset = chunk_offset + CRC_BYTES;
            let chunk_end = chunk_offset + chunk_bytes;

            result[chunk_offset..shard_offset].copy_from_slice(&crc32fast::hash(parity_shard).to_le_bytes());
            result[shard_offset..chunk_end].copy_from_slice(parity_shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let data_len = u32::from_le_bytes(encoded[..HEADER_BYTES].try_into()?) as usize;
        let total_shards = self.data_shards + self.parity_shards;
        let chunk_bytes = (encoded.len() - HEADER_BYTES) / total_shards;
        let shard_bytes = chunk_bytes - CRC_BYTES;

        let mut decoder = ReedSolomonDecoder::new(self.data_shards, self.parity_shards, shard_bytes)?;
        let mut shards: Vec<Option<&[u8]>> = vec![None; self.data_shards];

        for (idx, chunk) in encoded[HEADER_BYTES..].chunks_exact(chunk_bytes).enumerate() {
            let (stored_crc, shard) = chunk.split_at(CRC_BYTES);
            if stored_crc != crc32fast::hash(shard).to_le_bytes() {
                continue;
            }
            if idx < self.data_shards {
                decoder.add_original_shard(idx, shard)?;
                shards[idx] = Some(shard);
            } else {
                decoder.add_recovery_shard(idx - self.data_shards, shard)?;
            }
        }

        let decoded = decoder.decode()?;
        let recovered_map: HashMap<usize, &[u8]> = decoded.restored_original_iter().collect();

        let mut result = Vec::with_capacity(data_len);
        for (shard_idx, shard) in shards.into_iter().enumerate() {
            let shard = shard.or_else(|| recovered_map.get(&shard_idx).copied()).ok_or_else(|| anyhow::anyhow!("missing shard {shard_idx}"))?;
            result.extend_from_slice(shard);
        }
        result.truncate(data_len);

        Ok(result)
    }
}
