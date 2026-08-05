use crate::config::{CURRENT_VERSION, KEY_LEN, MAGIC_BYTES};

#[nutype::nutype(validate(predicate = |&m| m == MAGIC_BYTES), derive(Serialize, Deserialize))]
pub(crate) struct Magic(u32);

#[nutype::nutype(validate(predicate = |&v| v == CURRENT_VERSION), derive(Serialize, Deserialize))]
pub(crate) struct Version(u16);

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub(crate) struct KeyBytes(Vec<u8>);
