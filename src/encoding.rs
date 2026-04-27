use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use subtle::ConstantTimeEq;

const LEN_SIZE: usize = 4;
const CRC_SIZE: usize = 4;

pub struct Encoding {
    original_count: usize,
    recovery_count: usize,
}

impl Encoding {
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        anyhow::ensure!(reed_solomon_simd::ReedSolomonEncoder::supports(original_count, recovery_count), "unsupported shard config");

        Ok(Self { original_count, recovery_count })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.original_count).next_multiple_of(2);

        let mut shards: Vec<Vec<u8>> = data
            .chunks(shard_size)
            .map(|chunk| {
                let mut shard = chunk.to_vec();
                shard.resize(shard_size, 0);
                shard
            })
            .collect();
        shards.resize_with(self.original_count, || vec![0; shard_size]);

        let recovery = reed_solomon_simd::encode(self.original_count, self.recovery_count, &shards)?;
        let mut result = (data.len() as u32).to_le_bytes().to_vec();
        for shard in shards.iter().chain(&recovery) {
            result.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let original_size = LittleEndian::read_u32(data) as usize;
        let chunk_size = (data.len() - LEN_SIZE) / (self.original_count + self.recovery_count);

        let (original, recovery) = data[LEN_SIZE..]
            .chunks(chunk_size)
            .enumerate()
            .filter_map(|(i, chunk)| {
                let (crc, shard) = chunk.split_at(CRC_SIZE);
                bool::from(crc.ct_eq(&crc32fast::hash(shard).to_le_bytes())).then_some((i, shard))
            })
            .partition::<Vec<(usize, &[u8])>, _>(|(i, _)| *i < self.original_count);

        let restored = if original.len() == self.original_count {
            original.into_iter().map(|(i, d)| (i, d.to_vec())).collect()
        } else {
            let recovery: Vec<(usize, &[u8])> = recovery.into_iter().map(|(i, d)| (i - self.original_count, d)).collect();
            reed_solomon_simd::decode(self.original_count, self.recovery_count, original, recovery)?
        };

        let mut result: Vec<u8> = (0..self.original_count).flat_map(|i| restored[&i].iter().copied()).collect();
        result.truncate(original_size);

        Ok(result)
    }
}
