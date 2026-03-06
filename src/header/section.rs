use anyhow::{Context, Result};
use bytemuck::{Pod, Zeroable};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::encoding::Encoding;
use crate::secret::SecretBytes;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
#[allow(clippy::struct_field_names)]
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
        anyhow::ensure!(!salt.is_empty(), "salt is empty");
        anyhow::ensure!(!params.is_empty(), "params is empty");
        anyhow::ensure!(!metadata.is_empty(), "metadata is empty");
        anyhow::ensure!(!mac.is_empty(), "mac is empty");

        let salt = self.encoder.encode(salt).context("encode salt")?;
        let params = self.encoder.encode(params).context("encode params")?;
        let metadata = self.encoder.encode(metadata).context("encode metadata")?;
        let mac = self.encoder.encode(mac).context("encode mac")?;
        let frame = Frame {
            salt: u32::try_from(salt.len()).context("salt length overflow")?,
            params: u32::try_from(params.len()).context("params length overflow")?,
            metadata: u32::try_from(metadata.len()).context("metadata length overflow")?,
            mac: u32::try_from(mac.len()).context("mac length overflow")?,
        };

        let mut result = bytemuck::bytes_of(&frame).to_vec();
        result.extend(salt);
        result.extend(params);
        result.extend(metadata);
        result.extend(mac);

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<PackedSections> {
        let frame = self.read_frame(reader).await?;
        let salt = self.read_section(reader, frame.salt, "salt").await?;
        let params = self.read_section(reader, frame.params, "params").await?;
        let metadata = self.read_section(reader, frame.metadata, "metadata").await?;
        let mac = self.read_section(reader, frame.mac, "mac").await?;

        Ok(PackedSections { salt: SecretBytes::from_slice(&salt), params, metadata, mac: SecretBytes::from_slice(&mac) })
    }

    async fn read_frame<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Frame> {
        let mut frame = Frame::zeroed();
        reader.read_exact(bytemuck::bytes_of_mut(&mut frame)).await.context("read frame")?;
        Ok(frame)
    }

    async fn read_section<R: AsyncRead + Unpin>(&self, reader: &mut R, len: u32, name: &str) -> Result<Vec<u8>> {
        anyhow::ensure!(len > 0, "{name} section is empty");
        let mut buffer = BytesMut::zeroed(len as usize);
        reader.read_exact(&mut buffer).await.with_context(|| format!("read {name}"))?;
        self.encoder.decode(&buffer).with_context(|| format!("decode {name}"))
    }
}
