/// The Ed25519 field modulus `p = 2^255 - 19`, encoded little-endian.
const FIELD_P_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

pub(crate) fn r_encoding_has_canonical_y(r_bytes: &[u8; 32]) -> bool {
    let mut y = *r_bytes;
    y[31] &= 0x7f;
    let mut i = 32;
    while i > 0 {
        i -= 1;
        if y[i] < FIELD_P_BYTES[i] {
            return true;
        }
        if y[i] > FIELD_P_BYTES[i] {
            return false;
        }
    }
    false
}

/// Which acceptance rules the verifier applies.
///
/// This mirrors the two scalar entry points: [`Zip215`](Self::Zip215) matches
/// [`VerificationKey::verify_zebra`](crate::ed_sigs::VerificationKey::verify_zebra)
/// and [`Dalek`](Self::Dalek) matches
/// [`VerificationKey::verify_dalek`](crate::ed_sigs::VerificationKey::verify_dalek).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VerifyPolicy {
    /// ZIP-215 cofactored verification; accepts non-canonical point encodings.
    #[default]
    Zip215,
    /// Strict Dalek verification, including algebraic small-order rejection.
    Dalek,
}
