use anyhow::{Context, Result};

use crate::cipher::KeyDeriver;
use crate::files::{Files, Metadata};
use crate::header::Deserializer;
use crate::pipeline::{Operation, Pipeline};
use crate::secret::Secret;

pub(crate) async fn decrypt(source: &Files, target: &Files, secret: &Secret) -> Result<Metadata> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let writer = target.writer().await.context("failed to create target file")?;
    let header = Deserializer::from_reader(reader.get_mut()).await.context("failed to deserialize header")?;

    let key = KeyDeriver::new(secret)?;
    let keys = key.derive_keys(header.salt())?;
    if !header.verify(&keys.signer_key)? {
        anyhow::bail!("incorrect password or corrupted file");
    }

    let pipeline = Pipeline::new(&keys.primary_key, &keys.secondary_key, Operation::Decryption)?;
    pipeline.process(reader, writer, header.file_size()).await?;

    if !crate::files::hash::validate_hash(target, header.file_hash())? {
        anyhow::bail!("hash verification failed");
    }

    Ok(Metadata { name: header.file_name().to_owned(), size: header.file_size(), hash: header.file_hash().to_vec() })
}
