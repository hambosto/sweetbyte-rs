use anyhow::{Context, Result};
use block_padding::array::typenum::{U16, U32, U64, U128, Unsigned};
use block_padding::array::{Array, ArraySize};
use block_padding::{PaddedData, Padding, Pkcs7};

pub(crate) struct Pkcs7Padding {
    block_size: usize,
}

impl Pkcs7Padding {
    pub(crate) fn new(block_size: usize) -> Result<Self> {
        if !matches!(block_size, 16 | 32 | 64 | 128) {
            anyhow::bail!("invalid block size");
        }

        Ok(Self { block_size })
    }

    pub(crate) fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input data");
        }

        match self.block_size {
            16 => Self::pad_with::<U16>(data),
            32 => Self::pad_with::<U32>(data),
            64 => Self::pad_with::<U64>(data),
            128 => Self::pad_with::<U128>(data),
            _ => anyhow::bail!("unsupported block size"),
        }
    }

    pub(crate) fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input data");
        }

        match self.block_size {
            16 => Self::unpad_with::<U16>(data),
            32 => Self::unpad_with::<U32>(data),
            64 => Self::unpad_with::<U64>(data),
            128 => Self::unpad_with::<U128>(data),
            _ => anyhow::bail!("unsupported block size"),
        }
    }

    fn pad_with<B: ArraySize>(data: &[u8]) -> Result<Vec<u8>> {
        match Pkcs7::pad_detached::<B>(data) {
            PaddedData::Pad { blocks, tail_block } => {
                let total = blocks.len().saturating_mul(B::USIZE).saturating_add(B::USIZE);
                let mut padded = Vec::with_capacity(total);
                for block in blocks {
                    padded.extend_from_slice(block.as_slice());
                }
                padded.extend_from_slice(tail_block.as_slice());
                Ok(padded)
            }
            PaddedData::NoPad { blocks } => {
                let total = blocks.len().saturating_mul(B::USIZE);
                let mut padded = Vec::with_capacity(total);
                for block in blocks {
                    padded.extend_from_slice(block.as_slice());
                }
                Ok(padded)
            }
            PaddedData::Error => anyhow::bail!("invalid padding"),
        }
    }

    fn unpad_with<B: ArraySize + Unsigned>(data: &[u8]) -> Result<Vec<u8>> {
        let num_blocks = data.len().checked_div(B::USIZE).unwrap_or(0);
        let mut blocks = Vec::with_capacity(num_blocks);

        for block in data.chunks_exact(B::USIZE) {
            let mut array = Array::default();
            array.copy_from_slice(block);
            blocks.push(array);
        }
        let unpadded = Pkcs7::unpad_blocks::<B>(&blocks).context("failed to unpad data")?;

        Ok(unpadded.into())
    }
}
