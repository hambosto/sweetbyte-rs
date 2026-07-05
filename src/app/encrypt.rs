use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::cipher::Derive;
use crate::codec::{BlockSize, CompressionLevel};
use crate::config::{ARGON2_SALT_LEN, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::file::{Files, Metadata};
use crate::header::WriteHeader;
use crate::pipeline::{Pipeline, Processing};
use crate::secret::Secret;

pub(crate) async fn encrypt(source: &Files, target: &Files, secret: &Secret) -> Result<Metadata> {
    let mut writer = target.writer().await.context("failed to create target file")?;
    let reader = source.reader().await.context("failed to open source file")?;
    let metadata = source.metadata().await.context("failed to read metadata")?;

    let salt = Derive::generate_salt(ARGON2_SALT_LEN)?;
    let key = Derive::new(secret)?;
    let derived_keys = key.derive_keys(&salt)?;

    let header = WriteHeader::new(metadata.name, metadata.size, metadata.hash)?;
    let serialized = header.serialize(salt.expose_secret(), &derived_keys.signer_key).context("failed to serialize header")?;
    writer.write_all(&serialized).await.context("failed to write header")?;

    let engine = Pipeline::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Encryption, CompressionLevel::Fast, BlockSize::B128, ORIGINAL_COUNT, RECOVERY_COUNT)?;
    engine.process(reader, writer, metadata.size).await?;

    Ok(Metadata { name: header.name().to_owned(), size: header.size(), hash: header.hash().to_vec() })
}
