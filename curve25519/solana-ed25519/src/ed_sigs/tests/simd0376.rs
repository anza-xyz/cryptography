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

/// One of the four vectors under "Signatures with torsion components" in
/// SIMD-0376, transcribed verbatim from the proposal.
struct TorsionVector {
    /// Which small-order point was added to `A`, as its canonical encoding
    /// and its order, or `None` for the honest `A`.
    torsion_a: Option<(&'static str, u64)>,
    /// Which small-order point was added to `R`, likewise.
    torsion_r: Option<(&'static str, u64)>,
    a: &'static str,
    r: &'static str,
    s: &'static str,
    /// The "Expected results" table: (`verify_strict`, `verify`, this proposal).
    expected: (bool, bool, bool),
}

/// RFC 8032 section 7.1 TEST 1 secret key.
const SIMD0376_TORSION_SEED: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// The 9-byte ASCII message `SIMD-0376`.
const SIMD0376_TORSION_MSG: &[u8] = b"SIMD-0376";

const T_ORDER_8: (&str, u64) = (
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    8,
);
const T_ORDER_4: (&str, u64) = (
    "0000000000000000000000000000000000000000000000000000000000000080",
    4,
);
const T_ORDER_2: (&str, u64) = (
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    2,
);

const SIMD0376_TORSION_VECTORS: [TorsionVector; 4] = [
    // Vector 0: the unmodified RFC-8032 signature, as a control.
    TorsionVector {
        torsion_a: None,
        torsion_r: None,
        a: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        r: "378f3448cf68fc54d977c7367d4ef248fd05c1384bc8ab8c90ec3011e3d2cadb",
        s: "237f8b8042af663b4ad84d04d78aead91668aa243c2598027763ec74312bce0c",
        expected: (true, true, true),
    },
    // Vector 1: `T_A` is the order-8 point, `R` is honest.
    TorsionVector {
        torsion_a: Some(T_ORDER_8),
        torsion_r: None,
        a: "9158312a9a8d6e3b34c891d6d61444f8b8211c5117ebad15bdb0bd68b07e0245",
        r: "378f3448cf68fc54d977c7367d4ef248fd05c1384bc8ab8c90ec3011e3d2cadb",
        s: "ff5bd16bfb12ff7df68015870ff0d9f68fbabb71e811a6b700efa72f1e84cb08",
        expected: (false, false, true),
    },
    // Vector 2: `A` is honest, `T_R` is the order-8 point.
    TorsionVector {
        torsion_a: None,
        torsion_r: Some(T_ORDER_8),
        a: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        r: "d6e69141a5921217a696a5ed42292ed014a1ab5e7a982268f0d0716da8d05a55",
        s: "d51b3303a858f99f17e0418ae47d4198787740e3d2b0bc56a6a7f6d77aeb170a",
        expected: (false, false, true),
    },
    // Vector 3: `T_A` is the order-4 point, `T_R` is the order-2 point.
    TorsionVector {
        torsion_a: Some(T_ORDER_4),
        torsion_r: Some(T_ORDER_2),
        a: "ad38a8f0b22ab7ca46ecee7bbef12b5f336c182652fac34392f859dbd9666a7d",
        r: "b670cbb7309703ab268838c982b10db702fa3ec7b43754736f13cfee1c2d3524",
        s: "3388c63463dd67693a6aa65c3c9153254f23fe91a9d8089ee619a9d7b1c90201",
        expected: (false, false, true),
    },
];

fn decode_hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("test vector should be 32 hex-encoded bytes");
    out
}

/// The SIMD-0376 "Signatures with torsion components" vectors, checked in
/// three ways:
///
/// 1. each vector is regenerated from the seed and the stated `T_A`/`T_R`, so
///    the transcribed bytes are the ones the proposal's construction produces;
/// 2. this crate's `verify` (SIMD-0376) and `verify_dalek` (`verify_strict`)
///    give the accept/reject results in the proposal's table;
/// 3. `ed25519-dalek` 2.2.0's `verify_strict` and `verify` give the results
///    the proposal says were confirmed against that library, and its signer
///    reproduces vector 0.
#[test]
fn simd0376_torsion_component_vectors() {
    use crate::ed_sigs::scalar_from_sha512;
    use sha2::{Digest, Sha512, digest::Update};

    let seed = decode_hex32(SIMD0376_TORSION_SEED);
    let msg = SIMD0376_TORSION_MSG;
    assert_eq!(hex::encode(msg), "53494d442d30333736");

    // RFC 8032 key expansion, done by hand so that `a` and `r` are available
    // to the torsion-shift construction below.
    let expanded = Sha512::digest(seed);
    let a = {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&expanded[..32]);
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Scalar::from_bytes_mod_order(bytes)
    };
    let r = scalar_from_sha512(Sha512::default().chain(&expanded[32..]).chain(msg));

    // The same `a` the crate's signer derives.
    let sk = SigningKey::from(seed);
    assert_eq!(
        (ED25519_BASEPOINT_POINT * a).compress().to_bytes(),
        <[u8; 32]>::from(VerificationKey::from(&sk)),
    );

    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    for (i, v) in SIMD0376_TORSION_VECTORS.iter().enumerate() {
        let A_bytes = decode_hex32(v.a);
        let R_bytes = decode_hex32(v.r);
        let s_bytes = decode_hex32(v.s);

        // (1) Regenerate. The torsion encodings are among the canonical
        // small-order encodings, and have the orders the proposal states.
        let torsion = |t: Option<(&str, u64)>| -> EdwardsPoint {
            match t {
                None => EdwardsPoint::default(),
                Some((enc, order)) => {
                    let t = CompressedEdwardsY(decode_hex32(enc))
                        .decompress()
                        .expect("torsion encoding decodes");
                    assert!(EIGHT_TORSION.contains(&t));
                    assert!((t * Scalar::from(order)).is_identity());
                    assert!(!(t * Scalar::from(order / 2)).is_identity());
                    t
                }
            }
        };
        let (torsion_a, torsion_r) = (torsion(v.torsion_a), torsion(v.torsion_r));
        let (A_regen, sig_regen) = {
            let A = ED25519_BASEPOINT_POINT * a + torsion_a;
            let R = ED25519_BASEPOINT_POINT * r + torsion_r;
            let A_enc = A.compress().to_bytes();
            let R_enc = R.compress().to_bytes();
            let h = challenge_scalar(&R_enc, &A_enc, msg);
            let s = r + h * a;
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&R_enc);
            sig[32..].copy_from_slice(s.as_bytes());
            (A_enc, sig)
        };
        assert_eq!(
            hex::encode(A_regen),
            v.a,
            "vector {i}: A does not regenerate"
        );
        assert_eq!(
            hex::encode(&sig_regen[..32]),
            v.r,
            "vector {i}: R does not regenerate"
        );
        assert_eq!(
            hex::encode(&sig_regen[32..]),
            v.s,
            "vector {i}: S does not regenerate"
        );

        // Steps 1-5 pass on every vector, so only step 7 decides.
        assert!(CompressedEdwardsY(A_bytes).is_canonical());
        assert!(CompressedEdwardsY(R_bytes).is_canonical());
        assert!(Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_some());
        for bytes in [A_bytes, R_bytes] {
            let p = CompressedEdwardsY(bytes)
                .decompress()
                .expect("on the curve");
            assert!(!p.is_small_order());
        }

        // (2) This crate.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&R_bytes);
        sig_bytes[32..].copy_from_slice(&s_bytes);
        let sig = Signature::from(sig_bytes);
        let vk = VerificationKey::try_from(A_bytes).expect("A decodes");
        let (exp_strict, exp_cofactorless, exp_simd) = v.expected;
        assert_eq!(
            vk.verify_dalek(&sig, msg).is_ok(),
            exp_strict,
            "vector {i}: verify_dalek"
        );
        assert_eq!(vk.verify(&sig, msg).is_ok(), exp_simd, "vector {i}: verify");
        // Tampering with the message must still be rejected by the new rule.
        assert!(vk.verify(&sig, b"SIMD-0377").is_err());

        #[cfg(all(feature = "alloc", feature = "rand_core"))]
        {
            use crate::ed_sigs::batch;
            let mut bv = batch::Verifier::new();
            bv.queue((VerificationKeyBytes::from(A_bytes), sig, msg));
            assert_eq!(bv.verify().is_ok(), exp_simd, "vector {i}: batch");
        }

        // (3) ed25519-dalek 2.2.0.
        let dalek_vk = ed25519_dalek::VerifyingKey::from_bytes(&A_bytes).expect("A decodes");
        let dalek_sig = Signature::from_bytes(&sig_bytes);
        assert_eq!(
            dalek_vk.verify_strict(msg, &dalek_sig).is_ok(),
            exp_strict,
            "vector {i}: dalek verify_strict"
        );
        assert_eq!(
            ed25519_dalek::Verifier::verify(&dalek_vk, msg, &dalek_sig).is_ok(),
            exp_cofactorless,
            "vector {i}: dalek verify"
        );
        if i == 0 {
            use ed25519_dalek::Signer;
            assert_eq!(dalek_sk.sign(msg).to_bytes(), sig_bytes);
            assert_eq!(<[u8; 64]>::from(sk.sign(msg)), sig_bytes);
        }
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
