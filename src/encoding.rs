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
        let total_count = self.original_count.saturating_add(self.recovery_count);

        let mut original = vec![vec![0u8; shard_size]; self.original_count];
        for (shard, chunk) in original.iter_mut().zip(data.chunks(shard_size)) {
            let dest = shard.get_mut(..chunk.len()).context("chunk exceeds shard size")?;
            dest.copy_from_slice(chunk);
        }

        let recovery = reed_solomon_simd::encode(self.original_count, self.recovery_count, &original).context("failed to encode reed-solomon shards")?;

        let chunk_size = CRC_SIZE.saturating_add(shard_size);
        let payload_size = total_count.saturating_mul(chunk_size);
        let capacity = LEN_SIZE.saturating_add(payload_size);

        let mut result = Vec::with_capacity(capacity);
        result.extend_from_slice(&u32::try_from(data.len())?.to_le_bytes());

        for shard in original.iter().chain(&recovery) {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let len_bytes = data.get(..LEN_SIZE).context("data too short")?;
        let original_size = u32::from_le_bytes(len_bytes.try_into()?) as usize;
        let payload = data.get(LEN_SIZE..).context("data too short for payload")?;
        let chunk_size = payload.len().checked_div(self.original_count.saturating_add(self.recovery_count)).context("zero total shard count")?;

        let mut original = Vec::with_capacity(self.original_count);
        let mut recovery = Vec::with_capacity(self.recovery_count);

        for (index, chunk) in payload.chunks_exact(chunk_size).enumerate() {
            let (crc, shard) = chunk.split_at(CRC_SIZE);
            if !bool::from(crc.ct_eq(&crc32fast::hash(shard).to_le_bytes())) {
                continue;
            }
            if index < self.original_count {
                original.push((index, shard));
            } else {
                let recovery_index = index.saturating_sub(self.original_count);
                recovery.push((recovery_index, shard));
            }
        }

        let restored = if original.len() == self.original_count {
            original.into_iter().map(|(index, shard)| (index, shard.to_vec())).collect()
        } else {
            reed_solomon_simd::decode(self.original_count, self.recovery_count, original, recovery).context("failed to decode reed-solomon shards")?
        };

        let shard_size = chunk_size.saturating_sub(CRC_SIZE);
        let capacity = self.original_count.saturating_mul(shard_size);

        let mut result = Vec::with_capacity(capacity);
        for index in 0..self.original_count {
            result.extend_from_slice(restored.get(&index).with_context(|| format!("missing shard {index}"))?);
        }
        result.truncate(original_size);

        Ok(result)
    }
}
