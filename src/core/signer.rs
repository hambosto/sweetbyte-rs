use anyhow::{Context, Result};
use aws_lc_rs::hmac::{Context as Ctx, HMAC_SHA256, Key};
use subtle::ConstantTimeEq;

use crate::secret::Secret;
use crate::validation::KeyBytes32;

pub struct Signer {
    key: Secret,
}

impl Signer {
    pub fn new(key: &Secret) -> Result<Self> {
        let key = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn compute_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>> {
        if parts.is_empty() {
            anyhow::bail!("no input parts provided");
        }

        let mut total_len: usize = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.len() > 1 << 20 {
                anyhow::bail!("part {i} exceeds size limit");
            }

            total_len = total_len.saturating_add(part.len());
            if total_len > 1 << 24 {
                anyhow::bail!("total input size exceeds limit");
            }
        }

        let non_empty: Vec<&[u8]> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
        if non_empty.is_empty() {
            anyhow::bail!("all parts are empty");
        }
        let key = Key::new(HMAC_SHA256, self.key.expose_secret());

        let mut ctx = Ctx::with_key(&key);
        for part in non_empty {
            ctx.update(part);
        }

        Ok(ctx.sign().as_ref().to_vec())
    }

    pub fn verify_parts(&self, expected: &[u8], parts: &[&[u8]]) -> bool {
        self.compute_parts(parts).map(|computed| expected.ct_eq(&computed).into()).unwrap_or(false)
    }
}
