use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::cipher::KeyDeriver;
use crate::compression::CompressionLevel;
use crate::config::{ARGON2_SALT_LEN, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::files::{Files, Metadata};
use crate::header::Serializer;
use crate::padding::BlockSize;
use crate::pipeline::{Pipeline, Processing};
use crate::secret::Secret;

pub(crate) async fn encrypt(source: &Files, target: &Files, secret: &Secret) -> Result<Metadata> {
    let mut writer = target.writer().await.context("failed to create target file")?;
    let reader = source.reader().await.context("failed to open source file")?;
    let metadata = source.metadata().await.context("failed to read metadata")?;

    let salt = KeyDeriver::generate_salt(ARGON2_SALT_LEN)?;
    let key = KeyDeriver::new(secret)?;
    let keys = key.derive_keys(&salt)?;

    let header = Serializer::new(metadata.name, metadata.size, metadata.hash)?;
    let serialized = header.serialize(salt.expose_secret(), &keys.signer_key).context("failed to serialize header")?;
    writer.write_all(&serialized).await.context("failed to write header")?;

    let engine = Pipeline::new(&keys.primary_key, &keys.secondary_key, Processing::Encryption, CompressionLevel::Fast, BlockSize::B128, ORIGINAL_COUNT, RECOVERY_COUNT)?;
    engine.process(reader, writer, metadata.size).await?;

    Ok(Metadata { name: header.file_name().to_owned(), size: header.file_size(), hash: header.file_hash().to_vec() })
}
