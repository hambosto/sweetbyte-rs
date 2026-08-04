use crate::config::MAX_FILENAME_LEN;

#[nutype::nutype(validate(not_empty, len_char_max = MAX_FILENAME_LEN), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileSize(u64);

#[nutype::nutype(validate(predicate = |v| !v.is_empty()), derive(AsRef, Serialize, Deserialize))]
pub(crate) struct FileHash(Vec<u8>);
