use anyhow::Result;
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

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size)?;
        let mut result = Vec::with_capacity(4 + (4 + shard_size) * total_shards);
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());

        let mut shard = vec![0u8; shard_size];
        for i in 0..self.original_count {
            shard.fill(0);
            let start = i * shard_size;
            if start < data.len() {
                let end = (start + shard_size).min(data.len());
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
        let original_len = u32::from_le_bytes(encoded[..4].try_into()?) as usize;
        let total_shards = self.original_count + self.recovery_count;
        let encoded_data = &encoded[4..];

        let chunk_size = encoded_data.len() / total_shards;
        if chunk_size <= 4 {
            anyhow::bail!("shard size too small");
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
            let corrupted_count = total_shards - valid_count;
            anyhow::bail!("unrecoverable: {corrupted_count} corrupted shards exceeds recovery capacity ({})", self.recovery_count);
        }

        let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, shard_size)?;
        for (i, shard) in shards.iter().enumerate() {
            if let Some(s) = shard {
                if i < self.original_count {
                    decoder.add_original_shard(i, s)?;
                } else {
                    decoder.add_recovery_shard(i - self.original_count, s)?;
                }
            }
        }

        let restored = decoder.decode()?;
        let mut result = Vec::with_capacity(original_len);
        for (i, shard) in shards.iter_mut().enumerate().take(self.original_count) {
            let decoded_shard = shard.take().or_else(|| restored.restored_original(i)).ok_or_else(|| anyhow::anyhow!("missing shard {i}"))?;
            result.extend_from_slice(decoded_shard);
        }
        result.truncate(original_len);

        Ok(result)
    }
}
