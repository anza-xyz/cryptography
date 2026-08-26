use alloc::vec;
use alloc::vec::Vec;

use crate::ed_sigs::{
    Signature, SigningKey, VerificationKey, VerificationKeyBytes,
    avx512::{HotKeyCache, Verifier, VerifyInput, VerifyPolicy},
};
use crate::{constants::ED25519_BASEPOINT_POINT, ed_sigs::scalar_from_sha512, scalar::Scalar};
use sha2::{Sha512, digest::Update};

use super::small_order::low_order_encodings;

#[test]
fn simd_batch_reports_per_input_results() {
    let mut inputs = [VerifyInput {
        public_key: [0u8; 32],
        signature: [0u8; 64],
        message: b"simd batch",
    }; 8];

    for (i, input) in inputs.iter_mut().enumerate() {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let signing_key = SigningKey::from(seed);
        input.public_key = VerificationKeyBytes::from(&signing_key).into();
        input.signature = signing_key.sign(input.message).into();
    }
    inputs[3].signature[40] ^= 1;

    let mut out = [false; 8];
    Verifier::new()
        .expect("test is only compiled for AVX-512 builds")
        .verify_batch(&inputs, &mut out);

    for (i, input) in inputs.iter().enumerate() {
        let verification_key = VerificationKey::try_from(input.public_key)
            .expect("test signing key must produce a valid verification key");
        let signature = Signature::from(input.signature);
        assert_eq!(
            out[i],
            verification_key.verify(&signature, input.message).is_ok(),
            "lane {i} disagreed with scalar verification"
        );
    }
    assert_eq!(out, [true, true, true, false, true, true, true, true]);
}

#[allow(non_snake_case)]
fn forge_for_small_order_key(A_bytes: [u8; 32]) -> ([u8; 64], Vec<u8>) {
    let vk = VerificationKey::try_from(A_bytes).expect("small-order key decodes");
    let s = Scalar::from(1u64);
    let R_bytes = (ED25519_BASEPOINT_POINT * s).compress().to_bytes();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&R_bytes);
    signature[32..].copy_from_slice(s.as_bytes());

    for n in 0..64u32 {
        let message = std::format!("pay attacker {n}").into_bytes();
        let h = scalar_from_sha512(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&A_bytes[..])
                .chain(&message[..]),
        );
        let expected_R =
            crate::EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &vk.minus_A, &s)
                .compress();
        if expected_R.as_bytes() == &R_bytes {
            return (signature, message);
        }
    }

    panic!("failed to find deterministic small-order forgery");
}

#[test]
fn simd_dalek_rejects_small_order_forgery_with_and_without_cache() {
    for public_key in low_order_encodings() {
        let (signature, message) = forge_for_small_order_key(public_key);
        let input = VerifyInput {
            public_key,
            signature,
            message: &message,
        };
        let inputs = [input; 8];

        let mut out = [false; 8];
        Verifier::with_policy(VerifyPolicy::Dalek)
            .expect("test is only compiled for AVX-512 builds")
            .verify_batch(&inputs, &mut out);
        assert_eq!(out, [false; 8]);

        let mut cached = Verifier::with_cache(
            VerifyPolicy::Dalek,
            HotKeyCache::with_capacity(low_order_encodings().len()),
        )
        .expect("test is only compiled for AVX-512 builds");
        cached.verify_batch(&inputs, &mut out);
        assert_eq!(out, [false; 8]);
        cached.verify_batch(&inputs, &mut out);
        assert_eq!(out, [false; 8]);

        // ZIP-215 intentionally accepts the cofactored equation, proving the
        // key was not rejected globally before policy dispatch.
        Verifier::with_policy(VerifyPolicy::Zip215)
            .expect("test is only compiled for AVX-512 builds")
            .verify_batch(&inputs, &mut out);
        assert_eq!(out, [true; 8]);
    }
}

#[test]
fn sub_width_batch_matches_scalar_verification() {
    // Small batches are dispatched either to the scalar fallback (1-2 inputs)
    // or the padded SIMD chunk (3-7 inputs); check every size below the SIMD
    // width across that crossover, including a tampered signature.
    for len in 1..8usize {
        let mut inputs = Vec::with_capacity(len);
        for i in 0..len {
            let mut seed = [0u8; 32];
            seed[0] = i as u8 + 1;
            let signing_key = SigningKey::from(seed);
            let message: &[u8] = b"sub width batch";
            let mut signature: [u8; 64] = signing_key.sign(message).into();
            // Corrupt the last input so the fallback must reject a lane too.
            if i + 1 == len {
                signature[40] ^= 1;
            }
            inputs.push(VerifyInput {
                public_key: VerificationKeyBytes::from(&signing_key).into(),
                signature,
                message,
            });
        }

        let mut out = vec![false; len];
        Verifier::new()
            .expect("test is only compiled for AVX-512 builds")
            .verify_batch(&inputs, &mut out);

        for (i, input) in inputs.iter().enumerate() {
            let verification_key = VerificationKey::try_from(input.public_key)
                .expect("test signing key must produce a valid verification key");
            let signature = Signature::from(input.signature);
            assert_eq!(
                out[i],
                verification_key.verify(&signature, input.message).is_ok(),
                "len {len} lane {i} disagreed with scalar verification"
            );
        }
        // Only the final tampered signature should be rejected.
        assert!(out[..len - 1].iter().all(|&ok| ok));
        assert!(!out[len - 1]);
    }
}
