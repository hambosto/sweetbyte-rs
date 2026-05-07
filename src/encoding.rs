use anyhow::{Context, Result};
use subtle::ConstantTimeEq;

const LEN_SIZE: usize = 4;
const CRC_SIZE: usize = 4;

pub struct Encoding {
    original_count: usize,
    recovery_count: usize,
}

impl Encoding {
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !reed_solomon_simd::ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported shard config");
        }

        Ok(Self { original_count, recovery_count })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(2);
        let total_shards = self.original_count.saturating_add(self.recovery_count);

        let mut buffer = vec![0u8; shard_size.saturating_mul(self.original_count)];
        for (i, chunk) in data.chunks(shard_size).enumerate() {
            let start = i.saturating_mul(shard_size);
            let end = start.saturating_add(chunk.len());
            if let Some(target) = buffer.get_mut(start..end) {
                target.copy_from_slice(chunk);
            }
        }

        let shards: Vec<&[u8]> = buffer.chunks_exact(shard_size).collect();
        let recovery = reed_solomon_simd::encode(self.original_count, self.recovery_count, &shards).context("failed to encode reed-solomon shards")?;
        let len = u32::try_from(data.len()).context("data too large, maximum size is 4GB")?;

        let mut result = Vec::with_capacity(LEN_SIZE.saturating_add(CRC_SIZE.saturating_add(shard_size).saturating_mul(total_shards)));
        result.extend_from_slice(&len.to_le_bytes());

        for shard in shards.iter().chain(recovery.iter().map(|v| v.as_slice()).collect::<Vec<&[u8]>>().iter()) {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let len_bytes = data.get(..LEN_SIZE).context("data too short")?;
        let original_size = u32::from_le_bytes(len_bytes.try_into()?) as usize;
        let total_shards = self.original_count.checked_add(self.recovery_count).context("too many shards")?;
        let payload = data.get(LEN_SIZE..).context("data too short")?;
        let chunk_size = payload.len().checked_div(total_shards).context("invalid shard configuration")?;

        let mut original: Vec<(usize, &[u8])> = Vec::with_capacity(self.original_count);
        let mut recovery: Vec<(usize, &[u8])> = Vec::with_capacity(self.recovery_count);

        for (i, chunk) in payload.chunks(chunk_size).enumerate() {
            let (crc_bytes, shard) = chunk.split_at(CRC_SIZE);
            if bool::from(crc_bytes.ct_eq(&crc32fast::hash(shard).to_le_bytes())) {
                if i < self.original_count {
                    original.push((i, shard));
                } else {
                    recovery.push((i.saturating_sub(self.original_count), shard));
                }
            }
        }

        let mut result = Vec::with_capacity(original_size);
        if original.len() == self.original_count {
            for (_, shard) in &original {
                result.extend_from_slice(shard);
            }
        } else {
            let decoded = reed_solomon_simd::decode(self.original_count, self.recovery_count, original.iter().copied(), recovery.iter().copied()).context("failed to decode reed-solomon shards")?;
            for i in 0..self.original_count {
                result.extend_from_slice(decoded.get(&i).with_context(|| format!("missing shard {i}"))?);
            }
        }
        result.truncate(original_size);

        Ok(result)
    }
}
