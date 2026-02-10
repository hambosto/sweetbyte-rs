use anyhow::{Context, Result};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

const HEADER_SIZE: usize = 4;
const CRC_SIZE: usize = 4;
const ALIGNMENT: usize = 2;

pub struct Encoding {
    original_count: usize,
    recovery_count: usize,
}

impl Encoding {
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported configuration: {original_count} original + {recovery_count} recovery shards");
        }
        Ok(Self { original_count, recovery_count })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(ALIGNMENT);
        let total_shards = self.original_count + self.recovery_count;
        let shard_bytes = CRC_SIZE + shard_size;

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size).context("create encoder")?;

        let mut result = Vec::with_capacity(HEADER_SIZE + shard_bytes * total_shards);
        result.extend_from_slice(&u32::try_from(data.len()).context("data too large")?.to_le_bytes());

        let mut shard_buffer = vec![0u8; shard_size];
        for shard_index in 0..self.original_count {
            let start = shard_index * shard_size;
            let end = (start + shard_size).min(data.len());
            let bytes_written = end.saturating_sub(start);

            shard_buffer[..bytes_written].copy_from_slice(&data[start..end]);
            shard_buffer[bytes_written..].fill(0);

            encoder.add_original_shard(&shard_buffer).with_context(|| format!("add shard {shard_index}"))?;

            result.extend_from_slice(&crc32fast::hash(&shard_buffer).to_le_bytes());
            result.extend_from_slice(&shard_buffer);
        }

        let parity_shards = encoder.encode().context("encode")?;
        for shard in parity_shards.recovery_iter() {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded_data: &[u8]) -> Result<Vec<u8>> {
        if encoded_data.len() < HEADER_SIZE {
            anyhow::bail!("input too short: {} bytes (need at least {HEADER_SIZE})", encoded_data.len());
        }

        let original_size = u32::from_le_bytes(encoded_data[..HEADER_SIZE].try_into().context("parse header")?) as usize;

        let payload = &encoded_data[HEADER_SIZE..];
        let total_shards = self.original_count + self.recovery_count;

        if !payload.len().is_multiple_of(total_shards) {
            anyhow::bail!("invalid size: {} bytes cannot be divided into {} shards", payload.len(), total_shards);
        }

        let chunk_size = payload.len() / total_shards;
        if chunk_size <= CRC_SIZE {
            anyhow::bail!("shard too small: {chunk_size} bytes (need more than {CRC_SIZE})");
        }

        let shard_size = chunk_size - CRC_SIZE;
        let mut valid_shards = Vec::with_capacity(total_shards);

        for shard_chunk in payload.chunks_exact(chunk_size) {
            let (shard_crc, shard_data) = shard_chunk.split_at(CRC_SIZE);
            let computed_crc = crc32fast::hash(shard_data).to_le_bytes();
            valid_shards.push((shard_crc == computed_crc).then_some(shard_data));
        }

        let valid_count = valid_shards.iter().filter(|s| s.is_some()).count();
        if valid_count < self.original_count {
            anyhow::bail!("insufficient shards: {valid_count} valid (need {}) to recover", self.original_count);
        }

        let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, shard_size).context("create decoder")?;
        for (shard_index, shard_option) in valid_shards.iter().enumerate() {
            if let Some(shard) = shard_option {
                if shard_index < self.original_count {
                    decoder.add_original_shard(shard_index, shard).with_context(|| format!("add shard {shard_index}"))?;
                } else {
                    let recovery_index = shard_index - self.original_count;
                    decoder.add_recovery_shard(recovery_index, shard).with_context(|| format!("add recovery {recovery_index}"))?;
                }
            }
        }

        let restored = decoder.decode().context("decode")?;
        let mut recovered = vec![None; self.original_count];

        for (shard_index, shard) in restored.restored_original_iter() {
            if shard_index < self.original_count {
                recovered[shard_index] = Some(shard);
            }
        }

        let mut result = Vec::with_capacity(original_size);
        for shard_index in 0..self.original_count {
            let shard = valid_shards[shard_index].or(recovered[shard_index]).ok_or_else(|| anyhow::anyhow!("missing shard {shard_index}"))?;
            result.extend_from_slice(shard);
        }
        result.truncate(original_size);

        Ok(result)
    }
}
