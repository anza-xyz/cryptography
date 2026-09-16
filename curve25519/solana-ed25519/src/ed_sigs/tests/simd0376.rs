//! Conformance tests for the parts of [SIMD-0376] that the small-order test
//! vectors do not reach: the canonicity checks (steps 1 and 2), the relaxation
//! that the cofactored equation buys (step 7), and the backwards-compatibility
//! lemma relating the new rule to `verify_strict`.
//!
//! [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
#![cfg(feature = "std")]
#![allow(non_snake_case)]

use crate::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    ed_sigs::{
        Error, Signature, SigningKey, VerificationKey, VerificationKeyBytes, challenge_scalar,
    },
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use core::convert::TryFrom;

use super::util;

/// Build a signature that satisfies the cofactored equation but not the
/// cofactorless one, by adding a torsion point `T` to `A` or to `R`.
///
/// With `A = [a]B` and `R = [r]B`, setting `s = r + h·a` gives
/// `[8][s]B = [8]R + [8][h]A`. Adding `T` to either point leaves both sides of
/// the *cofactored* equation unchanged, since `[8]T = O`, but moves the
/// cofactorless one by `T` or `[h]T`.
fn torsion_shifted_signature(
    a: Scalar,
    r: Scalar,
    torsion: EdwardsPoint,
    shift_r: bool,
    msg: &[u8],
) -> ([u8; 32], [u8; 64]) {
    let A = ED25519_BASEPOINT_POINT * a;
    let R = ED25519_BASEPOINT_POINT * r;

    let (A_enc, R_enc) = if shift_r {
        (A, R + torsion)
    } else {
        (A + torsion, R)
    };
    let A_bytes = A_enc.compress().to_bytes();
    let R_bytes = R_enc.compress().to_bytes();

    let h = challenge_scalar(&R_bytes, &A_bytes, msg);
    let s = r + h * a;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&R_bytes);
    sig_bytes[32..].copy_from_slice(s.as_bytes());
    (A_bytes, sig_bytes)
}

/// The relaxation SIMD-0376 introduces: a point that *carries* a torsion
/// component but is not itself small-order is accepted, in either position.
/// These are exactly the signatures the proposal says were previously rejected
/// and may now be accepted, and they are why the change needs a feature gate.
#[test]
fn cofactored_equation_accepts_torsion_components() {
    let a = Scalar::from(0x5eed_1234_5678_9abcu64);
    let r = Scalar::from(0x0bad_cafe_dead_beefu64);
    let msg = b"torsion component";

    let mut shifted = 0usize;
    for torsion in EIGHT_TORSION.iter() {
        if torsion.is_identity() {
            // Adding the identity produces an ordinary signature, which both
            // rules accept; the interesting cases are the other seven.
            continue;
        }
        for shift_r in [false, true] {
            let (A_bytes, sig_bytes) = torsion_shifted_signature(a, r, *torsion, shift_r, msg);
            let sig = Signature::from(sig_bytes);
            let vk = VerificationKey::try_from(A_bytes).expect("shifted point is on the curve");

            // Steps 1, 2 and 5 pass: `compress` emits canonical encodings, and
            // a large-order point plus torsion is still large-order.
            let R_bytes: [u8; 32] = sig_bytes[..32].try_into().expect("R is 32 bytes");
            assert!(CompressedEdwardsY(A_bytes).is_canonical());
            assert!(CompressedEdwardsY(R_bytes).is_canonical());
            assert!(
                !CompressedEdwardsY(R_bytes)
                    .decompress()
                    .expect("decodes")
                    .is_small_order()
            );

            assert_eq!(
                vk.verify(&sig, msg),
                Ok(()),
                "cofactored rule rejected a torsion-shifted signature (shift_r={shift_r})"
            );
            assert_eq!(
                vk.verify_dalek(&sig, msg),
                Err(Error::InvalidSignature),
                "cofactorless rule accepted a torsion-shifted signature (shift_r={shift_r})"
            );
            shifted += 1;
        }
    }
    assert_eq!(shifted, 14);
}

/// Steps 1 and 2 reject every non-canonical encoding, including the twenty
/// that are not small-order and so are not covered by step 5.
#[test]
fn rejects_non_canonical_encodings() {
    let sk = SigningKey::from([7u8; 32]);
    let good_vkb = VerificationKeyBytes::from(&sk);
    let msg = b"non-canonical encoding";
    let good_sig: [u8; 64] = sk.sign(msg).into();

    let mut checked = 0usize;
    for encoding in util::non_canonical_point_encodings() {
        assert!(!CompressedEdwardsY(encoding).is_canonical());

        // As `A`: the key still decodes, so `try_from` succeeds and step 1
        // does the rejecting.
        let vk = VerificationKey::try_from(encoding).expect("non-canonical encodings decode");
        assert_eq!(
            vk.verify(&Signature::from(good_sig), msg),
            Err(Error::MalformedPublicKey),
            "accepted non-canonical A={}",
            hex::encode(encoding),
        );

        // As `R`.
        let mut sig_bytes = good_sig;
        sig_bytes[..32].copy_from_slice(&encoding);
        let vk = VerificationKey::try_from(good_vkb).expect("valid key");
        assert_eq!(
            vk.verify(&Signature::from(sig_bytes), msg),
            Err(Error::InvalidSignature),
            "accepted non-canonical R={}",
            hex::encode(encoding),
        );

        checked += 1;
    }
    assert_eq!(checked, 26);
}

/// Step 3: `s` must lie in `{0, ..., ℓ - 1}`. `s = ℓ` and `s = ℓ + 1` are the
/// smallest unreduced encodings, and adding `ℓ` to a valid `s` is the classic
/// malleability witness that step 3 closes (SUF-CMA).
#[test]
fn rejects_unreduced_s() {
    use crate::constants::BASEPOINT_ORDER;

    let sk = SigningKey::from([8u8; 32]);
    let vk = VerificationKey::from(&sk);
    let msg = b"unreduced s";
    let sig_bytes: [u8; 64] = sk.sign(msg).into();
    assert_eq!(vk.verify(&Signature::from(sig_bytes), msg), Ok(()));

    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        sig_bytes[32..].try_into().expect("s is 32 bytes"),
    ))
    .expect("a signed `s` is reduced");

    // `s + ℓ`, computed over the integers so that it stays unreduced.
    let mut malleated = sig_bytes;
    let mut carry = 0u16;
    for (i, out) in malleated[32..].iter_mut().enumerate() {
        let sum = u16::from(s.as_bytes()[i]) + u16::from(BASEPOINT_ORDER.to_bytes()[i]) + carry;
        *out = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "s + ℓ should fit in 32 bytes");
    assert_ne!(malleated, sig_bytes);

    assert_eq!(
        vk.verify(&Signature::from(malleated), msg),
        Err(Error::InvalidSignature),
    );
}

/// Step 4: an encoding that is canonical but is not the `y`-coordinate of any
/// curve point is rejected.
#[test]
fn rejects_off_curve_points() {
    let sk = SigningKey::from([9u8; 32]);
    let vkb = VerificationKeyBytes::from(&sk);
    let msg = b"off-curve R";
    let mut sig_bytes: [u8; 64] = sk.sign(msg).into();

    let off_curve = (0u16..=u16::MAX)
        .map(|candidate| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&candidate.to_le_bytes());
            bytes
        })
        .find(|bytes| CompressedEdwardsY(*bytes).decompress().is_none())
        .expect("some small y is not on the curve");
    assert!(CompressedEdwardsY(off_curve).is_canonical());

    assert_eq!(
        VerificationKey::try_from(off_curve),
        Err(Error::MalformedPublicKey)
    );

    sig_bytes[..32].copy_from_slice(&off_curve);
    let vk = VerificationKey::try_from(vkb).expect("valid key");
    assert_eq!(
        vk.verify(&Signature::from(sig_bytes), msg),
        Err(Error::InvalidSignature)
    );
}

/// The proposal's backwards-compatibility lemma: every signature that
/// `verify_strict` accepts, and whose `A` and `R` encodings are canonical, is
/// accepted by the new rule.
///
/// Honestly generated signatures are the case that matters — RFC-8032 `sign`
/// produces neither non-canonical encodings nor small-order points, so honest
/// parties are unaffected by steps 1-5.
#[test]
fn honest_signatures_are_accepted_by_both_rules() {
    for i in 0..64u8 {
        let sk = SigningKey::from([i; 32]);
        let vk = VerificationKey::from(&sk);
        let msg = std::format!("honest message {i}").into_bytes();
        let sig = sk.sign(&msg);

        assert_eq!(vk.verify_dalek(&sig, &msg), Ok(()));
        assert_eq!(vk.verify(&sig, &msg), Ok(()));

        // And the encodings really are canonical and large-order, so steps 1-5
        // are not what is doing the accepting.
        let A_bytes: [u8; 32] = vk.into();
        assert!(CompressedEdwardsY(A_bytes).is_canonical());
        assert!(CompressedEdwardsY(*sig.r_bytes()).is_canonical());

        // Flipping the message must be rejected by both.
        let wrong = b"wrong message";
        assert!(vk.verify_dalek(&sig, wrong).is_err());
        assert!(vk.verify(&sig, wrong).is_err());
    }
}

/// Batch verification must agree with individual verification on every case,
/// which is the property the cofactored equation exists to provide.
#[cfg(all(feature = "alloc", feature = "rand_core"))]
#[test]
fn batch_agrees_with_individual_on_torsion_components() {
    use crate::ed_sigs::batch;

    let a = Scalar::from(0x1111_2222_3333_4444u64);
    let r = Scalar::from(0x5555_6666_7777_8888u64);
    let msg = b"batched torsion";

    for torsion in EIGHT_TORSION.iter() {
        for shift_r in [false, true] {
            let (A_bytes, sig_bytes) = torsion_shifted_signature(a, r, *torsion, shift_r, msg);
            let vkb = VerificationKeyBytes::from(A_bytes);
            let sig = Signature::from(sig_bytes);

            let individual = VerificationKey::try_from(vkb).and_then(|vk| vk.verify(&sig, msg));

            let mut bv = batch::Verifier::new();
            bv.queue((vkb, sig, msg));

            assert_eq!(individual.is_ok(), bv.verify().is_ok());
            assert!(individual.is_ok());
        }
    }
}
