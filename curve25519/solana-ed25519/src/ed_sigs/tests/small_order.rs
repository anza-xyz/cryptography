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

/// Every byte string that decodes to a point of order dividing the cofactor 8.
pub(super) fn low_order_encodings() -> Vec<[u8; 32]> {
    let encodings = EIGHT_TORSION
        .iter()
        .map(|point| point.compress().to_bytes())
        .chain(util::non_canonical_point_encodings().into_iter().take(6))
        .collect::<Vec<_>>();

    assert_eq!(encodings.len(), 14);
    for encoding in &encodings {
        let point = CompressedEdwardsY(*encoding).decompress().expect("decodes");
        assert!(point.is_small_order());
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
            // The verification equation is [8][s]B = [8]R + [8][k]A.
            // If R, A are torsion points the LHS is 0, setting s = 0 makes RHS 0.
            let valid_zip215 = true;
            // Strict Dalek verification rejects small-order A and R before
            // evaluating the verification equation.
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

/// A small-order public key admits a signature equation without knowledge of
/// a private scalar; strict verification must reject it algebraically.
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

        let mut found = false;
        for n in 0..64u32 {
            let msg = std::format!("pay attacker {n}").into_bytes();
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

            assert_eq!(
                vk.verify_dalek(&sig, &msg),
                Err(crate::ed_sigs::Error::InvalidSignature),
                "forgery accepted for A={} msg={}",
                hex::encode(A_bytes),
                std::string::String::from_utf8_lossy(&msg),
            );
            if let Ok(dalek_key) = dalek_key.as_ref() {
                assert!(dalek_key.verify_strict(&msg, &dalek_sig).is_err());
            }
        }
        if found {
            forgeable += 1;
        }
    }

    assert_eq!(forgeable, 14);
}

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
        assert_eq!(ours, theirs);
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
        let batch_verification = bv.verify(rand::thread_rng());
        assert_eq!(individual_verification.is_ok(), batch_verification.is_ok());
    }
    Ok(())
}
