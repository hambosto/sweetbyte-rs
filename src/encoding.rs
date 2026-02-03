use anyhow::Result;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

pub struct Encoding {
    original_count: usize,
    recovery_count: usize,
}

impl Encoding {
    #[inline]
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        if !ReedSolomonEncoder::supports(original_count, recovery_count) {
            anyhow::bail!("unsupported shard count: {original_count} original, {recovery_count} recovery");
        }
        Ok(Self { original_count, recovery_count })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input");
        }

        let data_len = data.len();
        let shard_size = (data_len.div_ceil(self.original_count) + 1) & !1;
        let total_shards = self.original_count + self.recovery_count;

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size)?;
        let mut result = Vec::with_capacity(4 + (4 + shard_size) * total_shards);
        result.extend_from_slice(&(data_len as u32).to_le_bytes());

        let mut shard = vec![0u8; shard_size];

        for i in 0..self.original_count {
            shard.fill(0);
            let start = i * shard_size;
            if start < data_len {
                let end = (start + shard_size).min(data_len);
                shard[..end - start].copy_from_slice(&data[start..end]);
            }
            encoder.add_original_shard(&shard)?;
            result.extend_from_slice(&crc32fast::hash(&shard).to_le_bytes());
            result.extend_from_slice(&shard);
        }

        for recovery_shard in encoder.encode()?.recovery_iter() {
            result.extend_from_slice(&crc32fast::hash(recovery_shard).to_le_bytes());
            result.extend_from_slice(recovery_shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.len() < 4 {
            anyhow::bail!("encoded data too short");
        }

        let original_len = u32::from_le_bytes(encoded[..4].try_into()?) as usize;
        let total_shards = self.original_count + self.recovery_count;
        let encoded_data = &encoded[4..];

        if encoded_data.is_empty() || !encoded_data.len().is_multiple_of(total_shards) {
            anyhow::bail!("invalid encoded length");
        }

        let chunk_size = encoded_data.len() / total_shards;
        if chunk_size <= 4 {
            anyhow::bail!("shard too small");
        }
        let shard_size = chunk_size - 4;

        let mut valid_original = Vec::with_capacity(self.original_count);
        let mut valid_recovery = Vec::with_capacity(self.recovery_count);
        let mut corrupted = 0;

        for (i, chunk) in encoded_data.chunks_exact(chunk_size).enumerate() {
            let (crc, shard) = chunk.split_at(4);
            let expected_crc = crc32fast::hash(shard).to_le_bytes();

            if crc == expected_crc {
                if i < self.original_count {
                    valid_original.push((i, shard));
                } else {
                    valid_recovery.push((i - self.original_count, shard));
                }
            } else {
                corrupted += 1;
            }
        }

        if valid_original.len() + valid_recovery.len() < self.original_count {
            anyhow::bail!("unrecoverable: {corrupted} corrupted shards exceeds recovery capacity ({})", self.recovery_count);
        }

        if valid_original.len() == self.original_count {
            valid_original.sort_unstable_by_key(|(i, _)| *i);
            return Ok(valid_original.iter().flat_map(|(_, s)| *s).copied().take(original_len).collect());
        }

        let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, shard_size)?;

        for &(i, s) in &valid_original {
            decoder.add_original_shard(i, s)?;
        }
        for &(i, s) in &valid_recovery {
            decoder.add_recovery_shard(i, s)?;
        }

        let restored = decoder.decode()?;
        let mut result = Vec::with_capacity(original_len);

        for i in 0..self.original_count {
            let shard = valid_original
                .iter()
                .find_map(|&(idx, s)| (idx == i).then_some(s))
                .or_else(|| restored.restored_original(i))
                .ok_or_else(|| anyhow::anyhow!("missing shard {i}"))?;
            result.extend_from_slice(shard);
        }
        result.truncate(original_len);

        Ok(result)
    }
}
