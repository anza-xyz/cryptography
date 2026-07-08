use core::convert::TryFrom;

use crate::ed_sigs::{
    Signature, SigningKey, VerificationKey, VerificationKeyBytes,
    simd::{Verifier, VerifyInput},
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
