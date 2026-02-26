use anyhow::Result;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use subtle::ConstantTimeEq;

const LEN_SIZE: usize = 4;
const CRC_SIZE: usize = 4;

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
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(2);

        let mut encoder = ReedSolomonEncoder::new(self.original_count, self.recovery_count, shard_size)?;
        let mut shards = Vec::with_capacity(self.original_count);

        for i in 0..self.original_count {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            shard[..end - start].copy_from_slice(&data[start..end]);
            encoder.add_original_shard(&shard)?;
            shards.push(shard);
        }

        let mut result = Vec::with_capacity(LEN_SIZE + (CRC_SIZE + shard_size) * (self.original_count + self.recovery_count));
        result.extend_from_slice(&u32::try_from(data.len())?.to_le_bytes());

        for shard in &shards {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        let parity_shards = encoder.encode()?;
        for shard in parity_shards.recovery_iter() {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded_data: &[u8]) -> Result<Vec<u8>> {
        let original_size = u32::from_le_bytes(encoded_data[..LEN_SIZE].try_into()?) as usize;
        let chunk_size = (encoded_data.len() - LEN_SIZE) / (self.original_count + self.recovery_count);
        let shard_size = chunk_size - CRC_SIZE;

        let mut decoder = ReedSolomonDecoder::new(self.original_count, self.recovery_count, shard_size)?;
        let mut shards: Vec<Option<&[u8]>> = vec![None; self.original_count];

        for (idx, chunk) in encoded_data[LEN_SIZE..].chunks_exact(chunk_size).enumerate() {
            let (crc, data) = chunk.split_at(CRC_SIZE);
            let expected_crc = crc32fast::hash(data).to_le_bytes();
            if bool::from(crc.ct_eq(&expected_crc)) {
                if idx < self.original_count {
                    decoder.add_original_shard(idx, data)?;
                    shards[idx] = Some(data);
                } else {
                    decoder.add_recovery_shard(idx - self.original_count, data)?;
                }
            }
        }

        let restored = decoder.decode()?;
        let mut result = Vec::with_capacity(original_size);
        for (idx, shard) in shards.into_iter().enumerate() {
            if let Some(s) = shard {
                result.extend_from_slice(s);
            } else {
                let restored = restored.restored_original(idx).ok_or_else(|| anyhow::anyhow!("missing shard {idx}"))?;
                result.extend_from_slice(restored);
            }
        }
        result.truncate(original_size);

        Ok(result)
    }
}
