pub(crate) use crate::ed_sigs::legacy::{
    r_encoding_has_canonical_y, r_encoding_is_legacy_excluded,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VerifyPolicy {
    /// ZIP-215 cofactored verification; accepts non-canonical point encodings.
    #[default]
    Zip215,
    /// Dalek-style canonical-`R` verification with solana-ed25519 legacy filters.
    Dalek,
}
