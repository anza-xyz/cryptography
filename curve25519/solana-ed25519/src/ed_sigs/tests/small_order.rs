#![cfg(feature = "std")]

use crate::{
    constants::EIGHT_TORSION,
    ed_sigs::scalar_from_sha512,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use color_eyre::Report;
use once_cell::sync::Lazy;
use sha2::{Sha512, digest::Update};
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
        let A = CompressedEdwardsY(*A_bytes)
            .decompress()
            .expect("low-order public-key encoding must decode");
        for R_bytes in &encodings {
            let R = CompressedEdwardsY(*R_bytes)
                .decompress()
                .expect("low-order R encoding must decode");
            let sig_bytes = {
                let mut bytes = [0u8; 64];
                bytes[0..32].copy_from_slice(&R_bytes[..]);
                bytes[32..64].copy_from_slice(s.as_bytes());
                bytes
            };
            let vk_bytes = *A_bytes;
            // The verification equation is [8][s]B = [8]R + [8][k]A.
            // If R, A are torsion points the LHS is 0, setting s = 0 makes RHS 0.
            let valid_zip215 = true;
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
                valid_zip215,
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
    println!("{:#?}", *SMALL_ORDER_SIGS);
    Ok(())
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
            let h = scalar_from_sha512(
                Sha512::default()
                    .chain(&R_bytes[..])
                    .chain(&A_bytes[..])
                    .chain(&msg[..]),
            );
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
