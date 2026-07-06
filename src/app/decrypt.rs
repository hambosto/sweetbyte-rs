use anyhow::{Context, Result};

use crate::cipher::Derive;
use crate::compression::CompressionLevel;
use crate::config::{ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::file::{Files, Metadata};
use crate::header::ReadHeader;
use crate::padding::BlockSize;
use crate::pipeline::{Pipeline, Processing};
use crate::secret::Secret;

pub(crate) async fn decrypt(source: &Files, target: &Files, secret: &Secret) -> Result<Metadata> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let writer = target.writer().await.context("failed to create target file")?;
    let header = ReadHeader::from_reader(reader.get_mut()).await.context("failed to deserialize header")?;

    let key = Derive::new(secret)?;
    let derived_keys = key.derive_keys(header.salt())?;
    if !header.verify(&derived_keys.signer_key)? {
        anyhow::bail!("incorrect password or corrupted file");
    }

    let pipeline = Pipeline::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Decryption, CompressionLevel::Fast, BlockSize::B128, ORIGINAL_COUNT, RECOVERY_COUNT)?;
    pipeline.process(reader, writer, header.size()).await?;

    if !crate::file::hash::validate_hash(target, header.hash())? {
        anyhow::bail!("hash verification failed");
    }

    Ok(Metadata { name: header.name().to_owned(), size: header.size(), hash: header.hash().to_vec() })
}
