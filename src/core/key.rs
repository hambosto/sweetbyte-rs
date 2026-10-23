use crate::config::KEY_LEN;
use crate::core::Secret;

#[nutype::nutype(validate(predicate = |b| b.len() == KEY_LEN))]
pub(crate) struct KeyBytes(Vec<u8>);

pub(crate) struct KeyPair {
    pub primary_key: Secret,
    pub secondary_key: Secret,
    pub signer_key: Secret,
}
