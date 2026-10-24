use serde::{Deserialize, Serialize};

use super::Secret;

#[derive(Serialize, Deserialize)]
pub(crate) struct EncodedSection {
    #[serde(with = "hex")]
    pub(crate) salt: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) parameters: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) metadata: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) mac: Vec<u8>,
}

pub(crate) struct DecodedSection {
    pub(crate) salt: Secret,
    pub(crate) parameters: Secret,
    pub(crate) metadata: Secret,
    pub(crate) mac: Secret,
}
