use anyhow::{Context, Result};
use aws_lc_rs::hmac::{Context as HmacContext, HMAC_SHA256, Key};
use subtle::ConstantTimeEq;

use crate::secret::Secret;
use crate::validation::KeyBytes;

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

        let key = Key::new(HMAC_SHA256, self.key.expose_secret());
        let mut hmac_context = HmacContext::with_key(&key);

        for part in parts {
            let part_len: u64 = part.len().try_into().context("part length overflow")?;
            hmac_context.update(&part_len.to_be_bytes());
            hmac_context.update(part);
        }

        Ok(hmac_context.sign().as_ref().to_vec())
    }

    pub(crate) fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts).map(|computed| expected.ct_eq(&computed).into()).unwrap_or(false)
    }
}
