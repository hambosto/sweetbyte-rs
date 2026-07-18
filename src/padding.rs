use anyhow::{Context, Error, Result};
use block_padding::array::typenum::{U16, U32, U64, U128, Unsigned};
use block_padding::array::{Array, ArraySize};
use block_padding::{PaddedData, Padding, Pkcs7};

#[derive(Clone, Copy, Default)]
pub(crate) enum BlockSize {
    #[default]
    B16,
    B32,
    B64,
    B128,
}

impl TryFrom<usize> for BlockSize {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            16 => Ok(BlockSize::B16),
            32 => Ok(BlockSize::B32),
            64 => Ok(BlockSize::B64),
            128 => Ok(BlockSize::B128),
            _ => Err(anyhow::anyhow!("invalid block size: {value}. must be 16, 32, 64, or 128.")),
        }
    }
}

impl From<BlockSize> for usize {
    fn from(block_size: BlockSize) -> Self {
        match block_size {
            BlockSize::B16 => 16,
            BlockSize::B32 => 32,
            BlockSize::B64 => 64,
            BlockSize::B128 => 128,
        }
    }
}

pub(crate) struct Pkcs7Padding {
    block_size: BlockSize,
}

impl Pkcs7Padding {
    pub(crate) fn new(block_size: BlockSize) -> Result<Self> {
        let size: usize = block_size.into();

        if size > 255 {
            anyhow::bail!("block size {size} exceeds PKCS#7's maximum of 255 bytes");
        }

        Ok(Self { block_size })
    }

    #[inline]
    pub(crate) fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        match self.block_size {
            BlockSize::B16 => Self::pad_with::<U16>(data),
            BlockSize::B32 => Self::pad_with::<U32>(data),
            BlockSize::B64 => Self::pad_with::<U64>(data),
            BlockSize::B128 => Self::pad_with::<U128>(data),
        }
    }

    #[inline]
    pub(crate) fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        match self.block_size {
            BlockSize::B16 => Self::unpad_with::<U16>(data),
            BlockSize::B32 => Self::unpad_with::<U32>(data),
            BlockSize::B64 => Self::unpad_with::<U64>(data),
            BlockSize::B128 => Self::unpad_with::<U128>(data),
        }
    }

    #[inline]
    fn pad_with<B: ArraySize>(data: &[u8]) -> Result<Vec<u8>> {
        match Pkcs7::pad_detached::<B>(data) {
            PaddedData::Pad { blocks, tail_block } => {
                let total_len = blocks.len().saturating_mul(B::USIZE).saturating_add(B::USIZE);
                let mut result = Vec::with_capacity(total_len);
                for block in blocks {
                    result.extend_from_slice(block.as_slice());
                }
                result.extend_from_slice(tail_block.as_slice());
                Ok(result)
            }
            PaddedData::NoPad { blocks } => {
                let total_len = blocks.len().saturating_mul(B::USIZE);
                let mut result = Vec::with_capacity(total_len);
                for block in blocks {
                    result.extend_from_slice(block.as_slice());
                }
                Ok(result)
            }
            PaddedData::Error => anyhow::bail!("invalid padding"),
        }
    }

    #[inline]
    fn unpad_with<B: ArraySize + Unsigned>(data: &[u8]) -> Result<Vec<u8>> {
        let num_blocks = data.len().checked_div(B::USIZE).unwrap_or(0);
        let mut blocks = Vec::with_capacity(num_blocks);

        for chunk in data.chunks_exact(B::USIZE) {
            let mut arr = Array::default();
            arr.copy_from_slice(chunk);
            blocks.push(arr);
        }
        let unpadded = Pkcs7::unpad_blocks::<B>(&blocks).context("failed to unpad data: invalid padding")?;

        Ok(unpadded.to_vec())
    }
}
