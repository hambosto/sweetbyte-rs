use crate::config::{CURRENT_VERSION, MAGIC_BYTES};

#[nutype::nutype(validate(predicate = |&m| m == MAGIC_BYTES), derive(Serialize, Deserialize))]
pub(crate) struct Magic(u32);

#[nutype::nutype(validate(predicate = |&v| v == CURRENT_VERSION), derive(Serialize, Deserialize))]
pub(crate) struct Version(u16);
