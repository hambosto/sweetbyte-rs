use anyhow::{Context, Result};
use subtle::ConstantTimeEq;

const LEN: usize = 4;
const CRC: usize = 4;
const MIN: usize = 2;

pub(crate) struct Encoding {
    original_count: usize,
    recovery_count: usize,
    total_count: usize,
}

impl Encoding {
    pub(crate) fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !reed_solomon_simd::ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported shard config");
        }
        let total_count = original_count.saturating_add(recovery_count);

        Ok(Self { original_count, recovery_count, total_count })
    }

    pub(crate) fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(MIN).max(MIN);

        let mut original = vec![0u8; self.original_count.saturating_mul(shard_size)];
        for (shard, chunk) in original.chunks_mut(shard_size).zip(data.chunks(shard_size)) {
            let prefix = shard.get_mut(..chunk.len()).context("invalid shard slice")?;
            prefix.copy_from_slice(chunk);
        }

        let mut result = Vec::with_capacity(LEN.saturating_add(self.total_count.saturating_mul(CRC.saturating_add(shard_size))));
        result.extend_from_slice(&u32::try_from(data.len())?.to_le_bytes());

        let recovery = reed_solomon_simd::encode(self.original_count, self.recovery_count, original.chunks(shard_size)).context("failed to encode reed-solomon shards")?;
        for shard in original.chunks(shard_size).chain(recovery.iter().map(|v| v.as_slice())) {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub(crate) fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (len_bytes, shard_bytes) = data.split_at_checked(LEN).context("data too short")?;
        let len_bytes: [u8; LEN] = len_bytes.try_into().context("invalid header length")?;
        let original_size = u32::from_le_bytes(len_bytes) as usize;
        let shard_size = shard_bytes.len().checked_div(self.total_count).context("invalid shard count")?;
        if shard_size <= CRC {
            anyhow::bail!("invalid shard size");
        }

        let mut original = Vec::with_capacity(self.original_count);
        let mut recovery = Vec::with_capacity(self.recovery_count);

        for (index, chunk) in shard_bytes.chunks_exact(shard_size).enumerate() {
            let (crc, shard) = chunk.split_at(CRC);
            if !bool::from(crc.ct_eq(&crc32fast::hash(shard).to_le_bytes())) {
                continue;
            }
            if index < self.original_count {
                original.push((index, shard));
            } else {
                recovery.push((index.saturating_sub(self.original_count), shard));
            }
        }

        let restored = if original.len() == self.original_count {
            original.into_iter().map(|(index, shard)| (index, shard.to_vec())).collect()
        } else {
            reed_solomon_simd::decode(self.original_count, self.recovery_count, original, recovery).context("failed to decode reed-solomon shards")?
        };

        let mut result = Vec::with_capacity(self.original_count.saturating_mul(shard_size.saturating_sub(CRC)));
        for index in 0..self.original_count {
            result.extend_from_slice(restored.get(&index).with_context(|| format!("missing shard {index}"))?);
        }
        result.truncate(original_size);

        Ok(result)
    }
}
