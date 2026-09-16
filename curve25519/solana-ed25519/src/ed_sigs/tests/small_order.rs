#![cfg(feature = "std")]

use crate::{
    constants::EIGHT_TORSION,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use color_eyre::Report;
use once_cell::sync::Lazy;
use std::vec::Vec;

use super::util;
use util::TestCase;

/// Every byte string that decodes to a point of order dividing the cofactor 8:
/// the 8 canonical encodings of the 8-torsion points plus the 6 non-canonical
/// low-order encodings, 14 in total.
///
/// Note that each of the 8-torsion points has both a sign-bit-clear and a
/// sign-bit-set encoding, so any blacklist that lists only one of the two, or
/// only the canonical encodings, leaves low-order keys reachable.
pub fn low_order_encodings() -> Vec<[u8; 32]> {
    let encodings = EIGHT_TORSION
        .iter()
        .map(|point| point.compress().to_bytes())
        .chain(util::non_canonical_point_encodings().into_iter().take(6))
        .collect::<Vec<_>>();

    assert_eq!(encodings.len(), 14);
    for e in &encodings {
        let p = CompressedEdwardsY(*e).decompress().expect("decodes");
        assert!(p.is_small_order(), "{} is not small order", hex::encode(e));
    }
    encodings
}

#[allow(non_snake_case)]
pub static SMALL_ORDER_SIGS: Lazy<Vec<TestCase>> = Lazy::new(|| {
    let mut tests = Vec::new();
    let s = Scalar::ZERO;

    let encodings = low_order_encodings();

    /*
    for (i, e) in encodings.iter().enumerate() {
        println!("{}: {}", i, hex::encode(e));
    }
    */

    for A_bytes in &encodings {
        let A = CompressedEdwardsY(*A_bytes).decompress().unwrap();
        for R_bytes in &encodings {
            let R = CompressedEdwardsY(*R_bytes).decompress().unwrap();
            let sig_bytes = {
                let mut bytes = [0u8; 64];
                bytes[0..32].copy_from_slice(&R_bytes[..]);
                bytes[32..64].copy_from_slice(s.as_bytes());
                bytes
            };
            let vk_bytes = *A_bytes;
            // Unmodified ZIP-215 accepts every one of these: the verification
            // equation is [8][s]B = [8]R + [8][k]A, so torsion `R` and `A`
            // make the right-hand side the identity, and `s = 0` makes the
            // left-hand side the identity too, whatever the message.
            //
            // SIMD-0376 is ZIP-215's equation plus steps 1-5, and step 5
            // rejects small-order `A` and `R` before the equation is reached.
            // That is exactly the departure from ZIP-215 the proposal makes,
            // and it is what keeps `Pubkey::default()` unsignable.
            let valid_simd0376 = false;
            // The legacy rule (`verify_dalek`, matching dalek's
            // `verify_strict`) rejects small-order `A` and small-order `R`
            // outright, before the verification equation is evaluated. Every
            // case in this set has both, so none of them is legacy-valid —
            // including the cases where `R + [k]A = 0` genuinely holds, which
            // are exactly the forgeries that an encoding blacklist admits.
            // See `verify_dalek_rejects_forgeries_under_small_order_keys`.
            debug_assert!(A.is_small_order() && R.is_small_order());
            let valid_legacy = false;

            tests.push(TestCase {
                vk_bytes,
                sig_bytes,
                valid_legacy,
                valid_simd0376,
            })
        }
    }
    tests
});

#[test]
fn conformance() -> Result<(), Report> {
    for case in SMALL_ORDER_SIGS.iter() {
        case.check()?;
    }
    assert_eq!(SMALL_ORDER_SIGS.len(), 14 * 14);
    Ok(())
}

/// The eight canonical small-order encodings, transcribed from the
/// [SIMD-0376] test vectors.
///
/// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
const SIMD0376_CANONICAL_SMALL_ORDER: [&str; 8] = [
    "0000000000000000000000000000000000000000000000000000000000000000", // order 4
    "0000000000000000000000000000000000000000000000000000000000000080", // order 4
    "0100000000000000000000000000000000000000000000000000000000000000", // order 1
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
];

/// The six non-canonical encodings of small-order points, transcribed from the
/// SIMD-0376 test vectors. The first four have `y >= 2^255 - 19`; the last two
/// set the sign bit while the recovered `x` coordinate is zero.
const SIMD0376_NON_CANONICAL_SMALL_ORDER: [&str; 6] = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

fn decode_hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("test vector should be 32 hex-encoded bytes");
    out
}

/// The `SMALL_ORDER_ENCODINGS` constant that `verify_simd0376` compares
/// against must be exactly the compressed `EIGHT_TORSION`, and exactly the
/// eight canonical encodings SIMD-0376 lists.
#[test]
fn small_order_encodings_match_eight_torsion() {
    use crate::ed_sigs::SMALL_ORDER_ENCODINGS;

    // `EIGHT_TORSION` is not ordered by encoding, so compare as sets.
    let mut from_curve = EIGHT_TORSION
        .iter()
        .map(|p| p.compress().to_bytes())
        .collect::<Vec<_>>();
    from_curve.sort_unstable();

    let from_simd = SIMD0376_CANONICAL_SMALL_ORDER
        .iter()
        .map(|s| decode_hex32(s))
        .collect::<Vec<_>>();

    let mut ours = SMALL_ORDER_ENCODINGS.to_vec();
    ours.sort_unstable();

    assert_eq!(ours, from_curve);
    assert_eq!(ours, from_simd, "the SIMD list is ordered by encoding");

    // Each is canonical, so the byte comparison in `accepts_point_encoding`
    // is reached rather than short-circuited by the canonicity check, and
    // each really is small-order.
    for e in &SMALL_ORDER_ENCODINGS {
        assert!(CompressedEdwardsY(*e).is_canonical(), "{}", hex::encode(e));
        assert!(
            CompressedEdwardsY(*e)
                .decompress()
                .expect("decodes")
                .is_small_order()
        );
    }
}

/// The byte comparison in `accepts_point_encoding` replaces the algebraic test
/// `[8]P == O`. That substitution is only sound if `SMALL_ORDER_ENCODINGS` is
/// the *complete* set of canonical small-order encodings, and the test above
/// only shows it matches `EIGHT_TORSION` — it takes the completeness of
/// `EIGHT_TORSION` on faith. This test establishes it.
///
/// The counting argument: Edwards25519 has order `8L` with `L` prime and odd,
/// so `{P : [8]P = O}` is exactly the 2-Sylow subgroup, of order exactly 8.
/// Therefore any 8 *distinct* points that are each killed by 8 are all of
/// them. `compress` is injective and emits canonical bytes, so those 8 points
/// have exactly 8 canonical encodings, and nothing else canonical is
/// small-order.
///
/// What is checked here is the part that could actually drift: that the
/// constant holds 8 pairwise-distinct points, that each is killed by 8, and
/// that they are closed under addition and negation (so they really are the
/// subgroup, not 8 unrelated points).
#[test]
fn small_order_encodings_are_the_complete_torsion_subgroup() {
    use crate::constants::BASEPOINT_ORDER;
    use crate::ed_sigs::SMALL_ORDER_ENCODINGS;
    use crate::traits::IsIdentity;

    let points = SMALL_ORDER_ENCODINGS
        .iter()
        .map(|e| CompressedEdwardsY(*e).decompress().expect("decodes"))
        .collect::<Vec<_>>();

    // Pairwise distinct: 8 encodings that collide would mean the constant
    // covers fewer than 8 points, leaving small-order keys reachable.
    for (i, a) in SMALL_ORDER_ENCODINGS.iter().enumerate() {
        for b in SMALL_ORDER_ENCODINGS.iter().skip(i + 1) {
            assert_ne!(a, b, "duplicate entry {}", hex::encode(a));
        }
    }

    // Each is killed by the cofactor.
    for p in &points {
        assert!(p.mul_by_cofactor().is_identity());
    }

    // Closed under addition and negation, and contains the identity: with 8
    // distinct elements each killed by 8, this is the order-8 subgroup, which
    // the counting argument says is the whole solution set of `[8]P = O`.
    let encodings = SMALL_ORDER_ENCODINGS.to_vec();
    assert!(points.iter().any(|p| p.is_identity()));
    for a in &points {
        assert!(encodings.contains(&(-a).compress().to_bytes()));
        for b in &points {
            assert!(
                encodings.contains(&(a + b).compress().to_bytes()),
                "not closed under addition"
            );
        }
    }

    // The premise of the counting argument: `L` is odd, so the 2-Sylow
    // subgroup of a group of order `8L` has order exactly 8. (`L` being prime
    // is a curve parameter, not something a unit test can establish.)
    assert_eq!(BASEPOINT_ORDER.to_bytes()[0] & 1, 1, "L must be odd");

    // And the two tests agree on what "small order" means: the algebraic test
    // and the blacklist must give the same answer on every canonical encoding
    // this crate's own generators can produce.
    for i in 0..64u64 {
        let p = crate::constants::ED25519_BASEPOINT_POINT * Scalar::from(i);
        for candidate in [p, -p] {
            let bytes = candidate.compress().to_bytes();
            assert_eq!(
                candidate.is_small_order(),
                encodings.contains(&bytes),
                "algebraic test and blacklist disagree on {}",
                hex::encode(bytes),
            );
        }
    }
}

/// `SMALL_ORDER_ENCODINGS` must not be confused with libsodium 1.0.15's
/// `EXCLUDED_POINT_ENCODINGS`. Neither list contains the other, and
/// libsodium's is wrong in both directions — which is why SIMD-0376 derives
/// its list from the curve rather than hand-writing one, and why this crate's
/// constant is checked against `EIGHT_TORSION` above.
#[test]
fn libsodium_excluded_encodings_are_not_the_small_order_set() {
    use crate::ed_sigs::SMALL_ORDER_ENCODINGS;
    use util::EXCLUDED_POINT_ENCODINGS;

    // Too narrow: three canonical small-order encodings are absent from
    // libsodium's list, all of them sign-bit-set variants —
    // `0000..0080`, `26e8..fc85` and `c717..03fa`.
    let absent = SMALL_ORDER_ENCODINGS
        .iter()
        .filter(|e| !EXCLUDED_POINT_ENCODINGS.contains(e))
        .count();
    assert_eq!(absent, 3);

    // Too wide: four of libsodium's eleven are not small-order at all. Two are
    // large-order points and two are not points on the curve. They look like
    // corrupted sign-flips of the entries above them (`13e8..` for `26e8..`,
    // `b417..` for `c717..`).
    let not_small_order = EXCLUDED_POINT_ENCODINGS
        .iter()
        .filter(|e| {
            CompressedEdwardsY(**e)
                .decompress()
                .is_none_or(|p| !p.is_small_order())
        })
        .count();
    assert_eq!(not_small_order, 4);

    // Net effect: libsodium catches only 7 of the 14 byte strings that decode
    // to small-order points, so it leaves low-order keys reachable. Our rule
    // rejects all 14 — the canonical 8 here, the other 6 by canonicity.
    let covered = low_order_encodings()
        .iter()
        .filter(|e| EXCLUDED_POINT_ENCODINGS.contains(e))
        .count();
    assert_eq!(covered, 7);
    for e in low_order_encodings() {
        assert!(!crate::ed_sigs::accepts_point_encoding(&e));
    }
}

/// The six non-canonical small-order encodings must be rejected by steps 1 and
/// 2 (canonicity), not by step 5 — a blacklist of canonical encodings alone
/// would let them through.
#[test]
fn simd0376_non_canonical_small_order_encodings_are_not_canonical() {
    use crate::ed_sigs::SMALL_ORDER_ENCODINGS;

    let from_simd = SIMD0376_NON_CANONICAL_SMALL_ORDER
        .iter()
        .map(|s| decode_hex32(s))
        .collect::<Vec<_>>();

    let derived = util::non_canonical_point_encodings()
        .into_iter()
        .take(6)
        .collect::<Vec<_>>();

    for e in &from_simd {
        assert!(derived.contains(e), "{} not derived", hex::encode(e));
        assert!(!CompressedEdwardsY(*e).is_canonical(), "{}", hex::encode(e));
        assert!(
            CompressedEdwardsY(*e)
                .decompress()
                .expect("decodes")
                .is_small_order()
        );
        assert!(
            !SMALL_ORDER_ENCODINGS.contains(e),
            "{} is on the canonical blacklist, so the canonicity check would be untested",
            hex::encode(e),
        );
    }
    assert_eq!(from_simd.len(), derived.len());
}

/// All 196 combinations of the fourteen SIMD-0376 encodings as `A` and `R`
/// with `s = 0` must be rejected, individually and in a batch. These are the
/// combinations that unmodified ZIP-215 accepts.
#[test]
#[allow(non_snake_case)]
fn simd0376_rejects_all_small_order_combinations() {
    use crate::ed_sigs::{Error, Signature, VerificationKey, VerificationKeyBytes};
    use core::convert::TryFrom;

    let encodings = SIMD0376_CANONICAL_SMALL_ORDER
        .iter()
        .chain(SIMD0376_NON_CANONICAL_SMALL_ORDER.iter())
        .map(|s| decode_hex32(s))
        .collect::<Vec<_>>();
    assert_eq!(encodings.len(), 14);

    let msg = b"pay attacker";
    let mut checked = 0usize;
    for A_bytes in &encodings {
        for R_bytes in &encodings {
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(R_bytes);
            // `s = 0`, which is fully reduced, so step 3 does not reject.
            let sig = Signature::from(sig_bytes);
            let vkb = VerificationKeyBytes::from(*A_bytes);

            let vk = VerificationKey::try_from(vkb).expect("all fourteen decode to curve points");
            assert_eq!(
                vk.verify(&sig, msg),
                Err(Error::MalformedPublicKey),
                "accepted A={} R={}",
                hex::encode(A_bytes),
                hex::encode(R_bytes),
            );

            #[cfg(all(feature = "alloc", feature = "rand_core"))]
            {
                use crate::ed_sigs::batch;
                let mut bv = batch::Verifier::new();
                bv.queue((vkb, sig, msg));
                assert_eq!(bv.verify(), Err(Error::MalformedPublicKey));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 196);
}

/// SIMD-0376 singles this case out: the all-zero public key
/// (`Pubkey::default()`, the System Program ID) paired with the all-zero
/// 64-byte signature must be rejected for every message.
#[test]
fn simd0376_rejects_default_pubkey_with_zero_signature() {
    use crate::ed_sigs::{Error, Signature, VerificationKey};
    use core::convert::TryFrom;

    let vk = VerificationKey::try_from([0u8; 32]).expect("the all-zero encoding is on the curve");
    let sig = Signature::from([0u8; 64]);

    for n in 0..64u32 {
        let msg = std::format!("transfer everything {n}").into_bytes();
        assert_eq!(vk.verify(&sig, &msg), Err(Error::MalformedPublicKey));
        // The legacy rule rejects it too; this is not a behaviour change.
        assert_eq!(vk.verify_dalek(&sig, &msg), Err(Error::InvalidSignature));
    }
}

/// A signature under a small-order public key can be forged with no private
/// key: pick any `s`, set `R = [s]B`, and grind an attacker-chosen part of the
/// message until `[h](-A)` lands on the identity, which happens once every
/// `ord(A) <= 8` messages. `verify_dalek` must reject all of these, and it can
/// only do so by testing the order of `A` algebraically.
#[test]
#[allow(non_snake_case)]
fn verify_dalek_rejects_forgeries_under_small_order_keys() {
    use crate::constants::ED25519_BASEPOINT_POINT;
    use crate::ed_sigs::{Signature, VerificationKey};
    use core::convert::TryFrom;

    let s = Scalar::from(1u64);
    let R_bytes = (ED25519_BASEPOINT_POINT * s).compress().to_bytes();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&R_bytes);
    sig_bytes[32..].copy_from_slice(s.as_bytes());
    let sig = Signature::from(sig_bytes);

    let mut forgeable = 0usize;
    for A_bytes in low_order_encodings() {
        let vk = VerificationKey::try_from(A_bytes).expect("low-order keys decode");
        let dalek_key = ed25519_dalek::VerifyingKey::from_bytes(&A_bytes);
        let dalek_sig = Signature::from_bytes(&sig_bytes);

        // 64 attempts is ~8 times the expected number needed for ord(A) = 8.
        let mut found = false;
        for n in 0..64u32 {
            let msg = std::format!("pay attacker {n}").into_bytes();

            // The bare verification equation, with the order tests removed.
            let h = crate::ed_sigs::challenge_scalar(&R_bytes, &A_bytes, &msg);
            let expected_R =
                EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &vk.minus_A, &s).compress();
            if expected_R.as_bytes() != &R_bytes {
                continue;
            }
            found = true;

            // The equation holds, so only the small-order test stands between
            // this tuple and acceptance. It must reject, and it must agree
            // with the real `ed25519-dalek`.
            assert_eq!(
                vk.verify_dalek(&sig, &msg),
                Err(crate::ed_sigs::Error::InvalidSignature),
                "forgery accepted for A={} msg={}",
                hex::encode(A_bytes),
                std::string::String::from_utf8_lossy(&msg),
            );
            if let Ok(dalek_key) = dalek_key.as_ref() {
                assert!(
                    dalek_key.verify_strict(&msg, &dalek_sig).is_err(),
                    "ed25519-dalek verify_strict accepted a forgery for A={}",
                    hex::encode(A_bytes),
                );
            }
        }
        if found {
            forgeable += 1;
        }
    }

    // Assert that the test actually exercised a forgery for every encoding,
    // rather than silently finding none. The count is deterministic: `s`, `R`
    // and the candidate messages are all fixed, and `[h](-A)` is the identity
    // whenever `h ≡ 0 mod ord(A)`, so 64 candidates suffice for all
    // `ord(A) <= 8`.
    assert_eq!(
        forgeable, 14,
        "expected all 14 low-order encodings to admit a satisfied equation, got {forgeable}"
    );
}

/// `verify_dalek` must be accept/reject identical to
/// `ed25519_dalek::VerifyingKey::verify_strict` on the small-order vectors,
/// which are the cases where the two rules used to disagree.
#[test]
fn verify_dalek_matches_dalek_verify_strict_on_small_order_vectors() {
    use crate::ed_sigs::{Signature, VerificationKey};
    use core::convert::TryFrom;

    for case in SMALL_ORDER_SIGS.iter() {
        let msg = b"Zcash";
        let ours = VerificationKey::try_from(case.vk_bytes)
            .and_then(|vk| vk.verify_dalek(&Signature::from(case.sig_bytes), msg))
            .is_ok();
        let theirs = ed25519_dalek::VerifyingKey::from_bytes(&case.vk_bytes)
            .and_then(|vk| vk.verify_strict(msg, &Signature::from_bytes(&case.sig_bytes)))
            .is_ok();

        assert_eq!(
            ours,
            theirs,
            "verify_dalek/verify_strict disagree for vk={} sig={}",
            hex::encode(case.vk_bytes),
            hex::encode(case.sig_bytes),
        );
    }
}

#[cfg(all(feature = "alloc", feature = "rand_core"))]
#[test]
fn individual_matches_batch_verification() -> Result<(), Report> {
    use crate::ed_sigs::{VerificationKey, VerificationKeyBytes, batch};
    use core::convert::TryFrom;
    use ed25519::Signature;

    for case in SMALL_ORDER_SIGS.iter() {
        let msg = b"Zcash";
        let sig = Signature::from(case.sig_bytes);
        let vkb = VerificationKeyBytes::from(case.vk_bytes);
        let individual_verification =
            VerificationKey::try_from(vkb).and_then(|vk| vk.verify(&sig, msg));
        let mut bv = batch::Verifier::new();
        bv.queue((vkb, sig, msg));
        let batch_verification = bv.verify();
        assert_eq!(individual_verification.is_ok(), batch_verification.is_ok());
    }
    Ok(())
}
