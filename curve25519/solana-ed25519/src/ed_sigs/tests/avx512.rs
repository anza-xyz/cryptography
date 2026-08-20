use core::convert::TryFrom;

use alloc::vec;
use alloc::vec::Vec;

use crate::ed_sigs::{
    Signature, SigningKey, VerificationKey, VerificationKeyBytes,
    avx512::{Verifier, VerifyInput},
};

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
    Verifier::new().verify_batch(&inputs, &mut out);

    for (i, input) in inputs.iter().enumerate() {
        let verification_key = VerificationKey::try_from(input.public_key).unwrap();
        let signature = Signature::from(input.signature);
        assert_eq!(
            out[i],
            verification_key.verify(&signature, input.message).is_ok(),
            "lane {i} disagreed with scalar verification"
        );
    }
    assert_eq!(out, [true, true, true, false, true, true, true, true]);
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
        Verifier::new().verify_batch(&inputs, &mut out);

        for (i, input) in inputs.iter().enumerate() {
            let verification_key = VerificationKey::try_from(input.public_key).unwrap();
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
