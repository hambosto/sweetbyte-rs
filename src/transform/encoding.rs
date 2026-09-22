use anyhow::{Context, Result};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

const PREFIX_LEN: usize = 4;
const CRC_LEN: usize = 4;
const MIN_SHARD: usize = 2;

pub(crate) struct Encoding {
    original_count: usize,
    recovery_count: usize,
    total_count: usize,
}

impl Encoding {
    pub(crate) fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported shard config");
        }
        let total_count = original_count.saturating_add(recovery_count);

        Ok(Self { original_count, recovery_count, total_count })
    }

    pub(crate) fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(MIN_SHARD).max(MIN_SHARD);

        let mut original = vec![0; self.original_count.saturating_mul(shard_size)];
        let prefix = original.get_mut(..data.len()).context("invalid shard buffer")?;
        prefix.copy_from_slice(data);

        let stored = u32::try_from(data.len()).context("data size overflow")?;
        let mut result = Vec::with_capacity(PREFIX_LEN.saturating_add(self.total_count.saturating_mul(CRC_LEN.saturating_add(shard_size))));
        result.extend_from_slice(&stored.to_le_bytes());

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size).context("failed to init encoder")?;
        for shard in original.chunks(shard_size) {
            encoder.add_original_shard(shard).context("failed to add shard")?;
        }

        let recovery = encoder.encode().context("failed to encode shards")?;
        for shard in original.chunks(shard_size).chain(recovery.recovery_iter()) {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub(crate) fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (prefix, body) = data.split_at_checked(PREFIX_LEN).context("encoded data too short")?;
        let len_bytes: [u8; PREFIX_LEN] = prefix.try_into().context("invalid length prefix")?;
        let original_size = u32::from_le_bytes(len_bytes) as usize;

        let remainder = body.len().checked_rem(self.total_count).context("invalid shard count")?;
        if remainder != 0 {
            anyhow::bail!("invalid shard count");
        }

        let shard_size = body.len().checked_div(self.total_count).context("invalid shard count")?;
        if shard_size <= CRC_LEN {
            anyhow::bail!("invalid shard size");
        }

        let payload_size = shard_size.saturating_sub(CRC_LEN);
        let mut original = Vec::with_capacity(self.original_count);
        let mut recovery = Vec::with_capacity(self.recovery_count);

        for (index, chunk) in body.chunks_exact(shard_size).enumerate() {
            let (crc, shard) = chunk.split_at(CRC_LEN);
            if crc != crc32fast::hash(shard).to_le_bytes().as_slice() {
                continue;
            }

            if index < self.original_count {
                original.push((index, shard));
            } else {
                recovery.push((index.saturating_sub(self.original_count), shard));
            }
        }

        let mut result = Vec::with_capacity(self.original_count.saturating_mul(payload_size));
        if original.len() == self.original_count {
            for (_, shard) in original {
                result.extend_from_slice(shard);
            }
        } else {
            let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, payload_size).context("failed to init decoder")?;
            for (index, shard) in original.iter().copied() {
                decoder.add_original_shard(index, shard).context("failed to add shard")?;
            }

            for (index, shard) in recovery.iter().copied() {
                decoder.add_recovery_shard(index, shard).context("failed to add shard")?;
            }

            let restored = decoder.decode().context("failed to decode shards")?;
            let mut present = original.into_iter().peekable();
            for index in 0..self.original_count {
                if present.peek().is_some_and(|(present_index, _)| *present_index == index) {
                    let (_, shard) = present.next().context("missing present shard")?;
                    result.extend_from_slice(shard);
                } else {
                    let shard = restored.restored_original(index).context("failed to restore shard")?;
                    result.extend_from_slice(shard);
                }
            }
        }

        if result.len() < original_size {
            anyhow::bail!("encoded length mismatch");
        }

        result.truncate(original_size);

        Ok(result)
    }
}
