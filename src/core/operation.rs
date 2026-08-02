use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

#[non_exhaustive]
#[derive(Display, Clone, Copy, Eq, PartialEq, EnumIter, IntoStaticStr)]
pub(crate) enum Operation {
    #[strum(to_string = "Encrypt")]
    Encryption,
    #[strum(to_string = "Decrypt")]
    Decryption,
}

impl Operation {
    pub(crate) fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    pub(crate) fn is_encryption(self) -> bool {
        matches!(self, Self::Encryption)
    }
}
