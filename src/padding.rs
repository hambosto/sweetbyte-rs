use anyhow::{Context, Result};
use block_padding::array::typenum::{U16, U32, U64, U128, Unsigned};
use block_padding::array::{Array, ArraySize};
use block_padding::{Padding, Pkcs7};

use crate::validation::NonEmptyBytes;

#[derive(Clone, Copy, Debug, Default)]
pub enum BlockSize {
    #[default]
    B16,
    B32,
    B64,
    B128,
}

impl BlockSize {
    pub fn is_valid(self) -> bool {
        matches!(self, Self::B16 | Self::B32 | Self::B64 | Self::B128)
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

pub struct Pkcs7Padding {
    block_size: BlockSize,
}

impl Pkcs7Padding {
    pub fn new(block_size: BlockSize) -> Result<Self> {
        if !block_size.is_valid() {
            anyhow::bail!("invalid block size: must be 16, 32, 64, or 128");
        }

        Ok(Self { block_size })
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        match self.block_size {
            BlockSize::B16 => Self::pad_with::<U16>(data.as_ref()),
            BlockSize::B32 => Self::pad_with::<U32>(data.as_ref()),
            BlockSize::B64 => Self::pad_with::<U64>(data.as_ref()),
            BlockSize::B128 => Self::pad_with::<U128>(data.as_ref()),
        }
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        match self.block_size {
            BlockSize::B16 => Self::unpad_with::<U16>(data.as_ref()),
            BlockSize::B32 => Self::unpad_with::<U32>(data.as_ref()),
            BlockSize::B64 => Self::unpad_with::<U64>(data.as_ref()),
            BlockSize::B128 => Self::unpad_with::<U128>(data.as_ref()),
        }
    }

    fn pad_with<B: ArraySize>(data: &[u8]) -> Result<Vec<u8>> {
        match Pkcs7::pad_detached::<B>(data) {
            block_padding::PaddedData::Pad { blocks, tail_block } => {
                let total_len = blocks.len().saturating_mul(B::USIZE).saturating_add(B::USIZE);
                let mut result = Vec::with_capacity(total_len);
                for block in blocks {
                    result.extend_from_slice(block.as_slice());
                }
                result.extend_from_slice(tail_block.as_slice());
                Ok(result)
            }
            block_padding::PaddedData::NoPad { blocks } => {
                let total_len = blocks.len().saturating_mul(B::USIZE);
                let mut result = Vec::with_capacity(total_len);
                for block in blocks {
                    result.extend_from_slice(block.as_slice());
                }
                Ok(result)
            }
            block_padding::PaddedData::Error => anyhow::bail!("invalid padding"),
        }
    }

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
