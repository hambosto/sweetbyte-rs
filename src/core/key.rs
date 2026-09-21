use crate::config::KEY_LEN;

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub(crate) struct KeyBytes(Vec<u8>);
