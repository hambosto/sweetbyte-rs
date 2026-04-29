use anyhow::{Context, Result};
use bytemuck::{Pod, Zeroable};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::encoding::Encoding;
use crate::secret::SecretBytes;
use crate::validation::NonZeroU32;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Frame {
    salt: u32,
    params: u32,
    metadata: u32,
    mac: u32,
}

pub struct PackedSections {
    pub salt: SecretBytes,
    pub params: Vec<u8>,
    pub metadata: Vec<u8>,
    pub mac: SecretBytes,
}

pub struct SectionShield {
    encoder: Encoding,
}

impl SectionShield {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Self { encoder: Encoding::new(data_shards, parity_shards)? })
    }

    pub fn pack(&self, salt: &[u8], params: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let salt = self.encoder.encode(salt).context("failed to encode salt")?;
        let params = self.encoder.encode(params).context("failed to encode params")?;
        let metadata = self.encoder.encode(metadata).context("failed to encode metadata")?;
        let mac = self.encoder.encode(mac).context("failed to encode mac")?;
        let frame = Frame {
            salt: u32::try_from(salt.len()).context("salt length exceeds maximum")?,
            params: u32::try_from(params.len()).context("params length exceeds maximum")?,
            metadata: u32::try_from(metadata.len()).context("metadata length exceeds maximum")?,
            mac: u32::try_from(mac.len()).context("mac length exceeds maximum")?,
        };

        let mut result = bytemuck::bytes_of(&frame).to_vec();
        result.extend_from_slice(&salt);
        result.extend_from_slice(&params);
        result.extend_from_slice(&metadata);
        result.extend_from_slice(&mac);

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<PackedSections> {
        let frame = self.read_frame(reader).await?;
        let salt = self.read_section(reader, frame.salt).await?;
        let params = self.read_section(reader, frame.params).await?;
        let metadata = self.read_section(reader, frame.metadata).await?;
        let mac = self.read_section(reader, frame.mac).await?;

        Ok(PackedSections { salt: SecretBytes::new(salt), params, metadata, mac: SecretBytes::new(mac) })
    }

    async fn read_frame<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Frame> {
        let mut frame = Frame::zeroed();
        reader.read_exact(bytemuck::bytes_of_mut(&mut frame)).await.context("failed to read frame")?;

        NonZeroU32::try_new(frame.salt).context("salt must not be empty")?;
        NonZeroU32::try_new(frame.params).context("params must not be empty")?;
        NonZeroU32::try_new(frame.metadata).context("metadata must not be empty")?;
        NonZeroU32::try_new(frame.mac).context("mac must not be empty")?;

        Ok(frame)
    }

    async fn read_section<R: AsyncRead + Unpin>(&self, reader: &mut R, len: u32) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; len as usize];
        reader.read_exact(&mut buffer).await.context("failed to read section")?;
        self.encoder.decode(&buffer).context("failed to decode section")
    }
}
