use anyhow::{Context, Result};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

pub struct Encoding {
    original_count: usize,
    recovery_count: usize,
}

impl Encoding {
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported shard count: {original_count} original, {recovery_count} recovery");
        }

        Ok(Self { original_count, recovery_count })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = (data.len().div_ceil(self.original_count) | 1) + 1;
        let total_shards = self.original_count + self.recovery_count;

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size).context("create encoder")?;

        let mut result = Vec::with_capacity(4 + (4 + shard_size) * total_shards);
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());

        let mut shard = vec![0u8; shard_size];
        for i in 0..self.original_count {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());
            let written = end.saturating_sub(start);

            if written < shard_size {
                shard[written..].fill(0);
            }
            if written > 0 {
                shard[..written].copy_from_slice(&data[start..end]);
            }

            encoder.add_original_shard(&shard).with_context(|| format!("failed to add original shard {i}"))?;
            result.extend_from_slice(&crc32fast::hash(&shard).to_le_bytes());
            result.extend_from_slice(&shard);
        }

        let encoded = encoder.encode().context("encode")?;
        for recovery_shard in encoded.recovery_iter() {
            result.extend_from_slice(&crc32fast::hash(recovery_shard).to_le_bytes());
            result.extend_from_slice(recovery_shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let original_len = u32::from_le_bytes(encoded.get(..4).with_context(|| format!("too short: {} bytes", encoded.len()))?.try_into()?) as usize;

        let total_shards = self.original_count + self.recovery_count;
        let encoded_data = encoded.get(4..).context("missing shard data")?;

        let chunk_size = encoded_data
            .len()
            .checked_div(total_shards)
            .with_context(|| format!("{} not divisible by {total_shards}", encoded_data.len()))?;

        if chunk_size <= 4 {
            anyhow::bail!("chunk too small: {chunk_size}");
        }

        let shard_size = chunk_size - 4;
        let mut shards = Vec::with_capacity(total_shards);

        for chunk in encoded_data.chunks_exact(chunk_size) {
            let (crc, shard) = chunk.split_at(4);
            let expected_crc = crc32fast::hash(shard).to_le_bytes();
            shards.push((expected_crc == crc).then_some(shard));
        }

        let valid_count = shards.iter().filter(|s| s.is_some()).count();
        if valid_count < self.original_count {
            anyhow::bail!("unrecoverable: {} corrupted shards exceeds recovery capacity ({})", total_shards - valid_count, self.recovery_count);
        }

        let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, shard_size).context("create decoder")?;
        for (i, shard) in shards.iter().enumerate() {
            if let Some(s) = shard {
                if i < self.original_count {
                    decoder.add_original_shard(i, s).with_context(|| format!("add original shard {i}"))?;
                } else {
                    decoder
                        .add_recovery_shard(i - self.original_count, s)
                        .with_context(|| format!("add recovery shard {}", i - self.original_count))?;
                }
            }
        }

        let restored = decoder.decode().context("decode")?;
        let mut result = Vec::with_capacity(original_len);

        for (i, shard) in shards.iter().enumerate().take(self.original_count) {
            let shard_data = shard.or_else(|| restored.restored_original(i)).with_context(|| format!("shard {i} missing"))?;
            result.extend_from_slice(shard_data);
        }
        result.truncate(original_len);

        Ok(result)
    }
}
