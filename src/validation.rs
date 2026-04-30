use anyhow::Result;

use crate::config::{CURRENT_VERSION, KEY_SIZE, MAGIC_BYTES, MAX_FILENAME_LEN, SCRYPT_KEY_LEN};
use crate::secret::SecretBytes;

#[nutype::nutype(validate(not_empty, len_char_max = MAX_FILENAME_LEN), derive(AsRef, Serialize, Deserialize))]
pub struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(AsRef, Serialize, Deserialize))]
pub struct FileSize(u64);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef, Serialize, Deserialize))]
pub struct FileHash(Vec<u8>);

#[nutype::nutype(validate(predicate = |&m| m == MAGIC_BYTES), derive(Serialize, Deserialize))]
pub struct Magic(u32);

#[nutype::nutype(validate(predicate = |&v| v == CURRENT_VERSION), derive(Serialize, Deserialize))]
pub struct Version(u16);

#[nutype::nutype(validate(predicate = |&v| v > 0), derive(Deref))]
pub struct NonZeroU32(u32);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(Debug, Clone, AsRef))]
pub struct NonEmptyBytes(Vec<u8>);

impl NonEmptyBytes {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_SIZE), derive(Debug, TryFrom))]
pub struct KeyBytes32(Vec<u8>);

impl KeyBytes32 {
    pub fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.into_inner())
    }
}

#[nutype::nutype(validate(predicate = |b| b.len() == SCRYPT_KEY_LEN), derive(TryFrom))]
pub struct KeyBytes64(Vec<u8>);

impl KeyBytes64 {
    pub fn split(self) -> Result<(KeyBytes32, KeyBytes32)> {
        let bytes = self.into_inner();
        let (a, b) = bytes.split_at(SCRYPT_KEY_LEN);
        let first = KeyBytes32::try_new(a.to_vec())?;
        let second = KeyBytes32::try_new(b.to_vec())?;
        Ok((first, second))
    }
}
