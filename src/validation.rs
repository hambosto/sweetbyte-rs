use crate::config::{CURRENT_VERSION, KEY_LEN, MAGIC_BYTES, MAX_FILENAME_LEN, SCRYPT_KEY_LEN};
use crate::secret::SecretBytes;

pub trait IntoSecretBytes {
    fn into_secret(self) -> SecretBytes;
}

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

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef))]
pub struct NonEmptyBytes(Vec<u8>);

impl IntoSecretBytes for NonEmptyBytes {
    fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.into_inner())
    }
}

#[nutype::nutype(validate(predicate = |v| !v.is_empty()))]
pub struct NonEmptyKey(Vec<u8>);

impl IntoSecretBytes for NonEmptyKey {
    fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.into_inner())
    }
}

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub struct KeyBytes32(Vec<u8>);

impl IntoSecretBytes for KeyBytes32 {
    fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.into_inner())
    }
}

#[nutype::nutype(validate(predicate = |b| b.len() == SCRYPT_KEY_LEN))]
pub struct KeyBytes64(Vec<u8>);

impl IntoSecretBytes for KeyBytes64 {
    fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.into_inner())
    }
}
