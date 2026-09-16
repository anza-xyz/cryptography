//! Ed25519 signing and verification (SIMD-0376 / HEEA-accelerated).
//!
//! Verification follows [SIMD-0376], which is the cofactored verification
//! equation of [ZIP-215] combined with explicit rejection of non-canonical
//! encodings and of small-order `A` and `R`. See
//! [`VerificationKey::verify_simd0376`] for the algorithm.
//!
//! [`VerificationKey::verify_dalek`] retains the pre-SIMD-0376 rule, which is
//! accept/reject identical to `ed25519-dalek`'s `verify_strict`. Both are
//! provided because activating SIMD-0376 requires a feature gate, and a gated
//! validator must be able to evaluate either rule.
//!
//! [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
//! [ZIP-215]: https://zips.z.cash/zip-0215

use crate::{edwards::CompressedEdwardsY, scalar::Scalar};
use sha2::{Digest, Sha512, digest::Update};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
pub mod batch;
mod bip32;
mod error;
mod signing_key;
mod verification_key;

// Allows importing traits used by `Signature`.
pub use ::ed25519;
pub use ::ed25519::Signature;
pub use bip32::{BIP32_HARDENED_INDEX_FLAG, Bip32DerivationError, ExtendedSigningKey};
pub use error::Error;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

/// The eight canonical encodings of the order-8 torsion subgroup of
/// Edwards25519, in the order listed by [SIMD-0376].
///
/// These are the compressed encodings of [`crate::constants::EIGHT_TORSION`];
/// `small_order_encodings_match_eight_torsion` asserts the two agree. They are
/// spelled out here because they are consensus constants, and because
/// comparing against them is cheaper than three point doublings.
///
/// # Equivalence to `[8]P == O`, and its precondition
///
/// Testing membership in this list is equivalent to the algebraic small-order
/// test `[8]P == O` — but *only on canonical input*.
///
/// Edwards25519 has order `8L` with `L` odd, so `{P : [8]P = O}` is its
/// 2-Sylow subgroup and has exactly 8 elements. `compress` is injective and
/// emits canonical bytes, so those 8 points have exactly these 8 canonical
/// encodings, and no other canonical encoding is small-order.
///
/// The equivalence fails on non-canonical input: six further byte strings also
/// decode to small-order points — `0100..0080`, the identity with the sign bit
/// set, among them — and none of them appear below. `accepts_point_encoding`
/// therefore applies [`CompressedEdwardsY::is_canonical`] first. Reversing the
/// two checks would leave small-order keys reachable.
///
/// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
pub const SMALL_ORDER_ENCODINGS: [[u8; 32]; 8] = [
    // 0000000000000000000000000000000000000000000000000000000000000000 (order 4)
    // Also `Pubkey::default()` and the System Program ID.
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 0000000000000000000000000000000000000000000000000000000000000080 (order 4)
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
    // 0100000000000000000000000000000000000000000000000000000000000000 (order 1)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 (order 8)
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 (order 8)
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    // c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a (order 8)
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa (order 8)
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
    // ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Steps 1, 2 and 5 of the [SIMD-0376] verification algorithm, applied to one
/// 32-byte point encoding (`A` or `R`).
///
/// Returns `false` if `bytes` is not a canonical encoding, or if it is one of
/// the eight canonical small-order encodings.
///
/// The small-order test is a byte-string comparison rather than a cofactor
/// multiplication, which SIMD-0376 permits precisely because the canonicity
/// check runs first: every small-order point that has a non-canonical encoding
/// has already been rejected by the time the comparison is reached. Testing
/// the encodings in the other order would be wrong.
///
/// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
pub(crate) fn accepts_point_encoding(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).is_canonical()
        && !SMALL_ORDER_ENCODINGS.iter().any(|small| small == bytes)
}

/// Step 6 of the [SIMD-0376] verification algorithm: the challenge scalar
/// `h = SHA512(R_bytes ‖ A_bytes ‖ M) mod ℓ`.
///
/// Every verification path must agree on this byte-for-byte — it is what binds
/// a signature to its message and key — so single, batched, and prehashed
/// verification all go through here.
///
/// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
#[allow(non_snake_case)]
pub(crate) fn challenge_scalar(R_bytes: &[u8; 32], A_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
    scalar_from_sha512(
        Sha512::default()
            .chain(&R_bytes[..])
            .chain(&A_bytes[..])
            .chain(msg),
    )
}

pub(crate) fn scalar_from_sha512(hash: Sha512) -> Scalar {
    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut output = hash.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(output.as_slice());
    let scalar = Scalar::from_bytes_mod_order_wide(&bytes);

    #[cfg(feature = "zeroize")]
    {
        output.zeroize();
        bytes.zeroize();
    }

    scalar
}
