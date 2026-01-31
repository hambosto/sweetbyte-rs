use anyhow::Result;
use reed_solomon_erasure::galois_8::ReedSolomon;

pub struct Encoding {
    encoder: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;
        Ok(Self { encoder, data_shards, parity_shards })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input");
        }

        let shard_size = data.len().div_ceil(self.data_shards);
        let total_shards = self.data_shards + self.parity_shards;

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        for chunk in data.chunks(shard_size) {
            let mut shard = vec![0u8; shard_size];
            shard[..chunk.len()].copy_from_slice(chunk);
            shards.push(shard);
        }

        shards.resize_with(total_shards, || vec![0u8; shard_size]);

        self.encoder.encode(&mut shards)?;

        let mut result = Vec::with_capacity(shard_size * total_shards);
        for shard in shards {
            result.extend_from_slice(&shard);
        }

        Ok(result)
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            anyhow::bail!("empty encoded data");
        }

        let total_shards = self.data_shards + self.parity_shards;
        if !encoded.len().is_multiple_of(total_shards) {
            anyhow::bail!("invalid encoded length: {} not divisible by shards ({})", encoded.len(), total_shards);
        }

        let shard_size = encoded.len() / total_shards;

        let mut shards: Vec<Option<Vec<u8>>> = encoded.chunks_exact(shard_size).map(|chunk| Some(chunk.to_vec())).collect();

        self.encoder.reconstruct(&mut shards)?;

        let mut result = Vec::with_capacity(self.data_shards * shard_size);
        for shard in shards.iter().take(self.data_shards).flatten() {
            result.extend_from_slice(shard);
        }

        Ok(result)
    }
}
