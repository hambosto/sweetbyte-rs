use crate::config::MAX_FILENAME_LEN;
use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[nutype::nutype(
    validate(not_empty, len_char_max = MAX_FILENAME_LEN),
    derive(Debug, Clone, AsRef, Serialize, Deserialize)
)]
pub struct Filename(String);

#[nutype::nutype(validate(greater = 0), derive(Debug, Clone, AsRef, Serialize, Deserialize))]
pub struct FileSize(u64);

#[nutype::nutype(
    validate(predicate = |v| !v.is_empty()),
    derive(Debug, Clone, AsRef, Serialize, Deserialize)
)]
pub struct FileHash(Vec<u8>);

#[nutype::nutype(
    validate(predicate = |&m| m == MAGIC_BYTES),
    derive(Debug, Clone, Copy, AsRef, Serialize, Deserialize)
)]
pub struct Magic(u32);

#[nutype::nutype(
    validate(predicate = |&v| v == CURRENT_VERSION),
    derive(Debug, Clone, Copy, AsRef, Serialize, Deserialize)
)]
pub struct Version(u16);

#[nutype::nutype(
    validate(predicate = |v| !v.is_empty()),
    derive(Debug, Clone, AsRef, Serialize, Deserialize)
)]
pub struct NonEmptyBytes(Vec<u8>);

#[nutype::nutype(
    validate(predicate = |&v| v > 0),
    derive(Debug, Clone, Copy, Deref)
)]
pub struct NonZeroU32(u32);
