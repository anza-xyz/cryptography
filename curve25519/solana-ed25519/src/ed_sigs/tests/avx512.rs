use super::small_order::SMALL_ORDER_SIGS;
use crate::ed_sigs::{
    Signature, SigningKey, VerificationKey, VerificationKeyBytes,
    avx512::{DalekVerifier, VerifyInput, Zip215Verifier},
};
use core::convert::TryFrom;
use std::{format, vec, vec::Vec};

#[derive(Debug)]
struct Case {
    public_key: [u8; 32],
    signature: [u8; 64],
    message: Vec<u8>,
}

fn expected(inputs: &[VerifyInput<'_>], dalek: bool) -> Vec<bool> {
    inputs
        .iter()
        .map(|input| {
            let signature = Signature::from(input.signature);
            VerificationKey::try_from(input.public_key)
                .and_then(|key| {
                    if dalek {
                        key.verify_dalek(&signature, input.message)
                    } else {
                        key.verify_zebra(&signature, input.message)
                    }
                })
                .is_ok()
        })
        .collect()
}

#[test]
fn simd_verifiers_match_scalar_verification() {
    let mut cases: Vec<Case> = (0..17u8)
        .map(|index| {
            let mut seed = [0u8; 32];
            seed[0] = index;
            let signing_key = SigningKey::from(seed);
            let message = format!("AVX-512 compatibility case {index}").into_bytes();
            Case {
                public_key: VerificationKeyBytes::from(&signing_key).into(),
                signature: signing_key.sign(&message).into(),
                message,
            }
        })
        .collect();

    // Exercise per-lane failure reporting and a partial final SIMD chunk.
    cases[5].message.push(0);
    cases[13].signature[17] ^= 1;

    let inputs: Vec<VerifyInput<'_>> = cases
        .iter()
        .map(|case| VerifyInput {
            public_key: case.public_key,
            signature: case.signature,
            message: &case.message,
        })
        .collect();

    let mut zip215 = Zip215Verifier::new();
    let mut zip215_out = vec![false; inputs.len()];
    zip215.verify_batch(&inputs, &mut zip215_out);
    assert_eq!(zip215_out, expected(&inputs, false));

    let mut dalek = DalekVerifier::new();
    let mut dalek_out = vec![false; inputs.len()];
    dalek.verify_batch(&inputs, &mut dalek_out);
    assert_eq!(dalek_out, expected(&inputs, true));
}

#[test]
fn simd_verifiers_match_current_small_order_rules() {
    let inputs: Vec<VerifyInput<'_>> = SMALL_ORDER_SIGS
        .iter()
        .map(|case| VerifyInput {
            public_key: case.vk_bytes,
            signature: case.sig_bytes,
            message: b"Zcash",
        })
        .collect();

    let mut zip215 = Zip215Verifier::new();
    let mut zip215_out = vec![false; inputs.len()];
    zip215.verify_batch(&inputs, &mut zip215_out);
    assert!(zip215_out.iter().all(|valid| *valid));

    let mut dalek = DalekVerifier::new();
    let mut dalek_out = vec![true; inputs.len()];
    dalek.verify_batch(&inputs, &mut dalek_out);
    assert!(dalek_out.iter().all(|valid| !*valid));
}
