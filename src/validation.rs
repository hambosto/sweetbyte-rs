use crate::config::{CURRENT_VERSION, KEY_LEN, MAGIC_BYTES, MAX_FILENAME_LEN};
use crate::secret::Secret;

#[nutype::nutype(validate(not_empty, len_char_max = MAX_FILENAME_LEN), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileSize(u64);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileHash(Vec<u8>);

#[nutype::nutype(validate(predicate = |&m| m == MAGIC_BYTES), derive(Serialize, Deserialize))]
pub(crate) struct Magic(u32);

#[nutype::nutype(validate(predicate = |&v| v == CURRENT_VERSION), derive(Serialize, Deserialize))]
pub(crate) struct Version(u16);

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub(crate) struct KeyBytes(Vec<u8>);

impl KeyBytes {
    pub(crate) fn into_secret(self) -> Secret {
        Secret::new(self.into_inner())
    }
}
