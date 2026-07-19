use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::secret::Secret;
use crate::validation::KeyBytes;

const MAX_PARTS: usize = 1 << 10;
const MAX_PART_LEN: usize = 1 << 20;
const MAX_TOTAL_LEN: usize = 1 << 24;

pub(crate) struct Signer {
    key: Secret,
}

impl Signer {
    pub(crate) fn new(key: &Secret) -> Result<Self> {
        let key = KeyBytes::try_new(key.expose_secret().to_vec()).context("key must be 32 bytes")?;

        Ok(Self { key: key.into_secret() })
    }

    pub(crate) fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        if parts.is_empty() {
            anyhow::bail!("no input parts provided");
        }

        if parts.len() > MAX_PARTS {
            anyhow::bail!("too many input parts");
        }

        let mut total_len: usize = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.len() > MAX_PART_LEN {
                anyhow::bail!("part {i} exceeds size limit");
            }

            total_len = total_len.saturating_add(part.len());
            if total_len > MAX_TOTAL_LEN {
                anyhow::bail!("total input size exceeds limit");
            }
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose_secret()).context("failed to setup key")?;

        for part in parts {
            let part_len: u64 = part.len().try_into().context("part length overflow")?;
            mac.update(&part_len.to_be_bytes());
            mac.update(part);
        }

        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub(crate) fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts).is_ok_and(|computed| expected.ct_eq(&computed).into())
    }
}
