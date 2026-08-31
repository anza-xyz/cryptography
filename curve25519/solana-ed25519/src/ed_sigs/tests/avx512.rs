use super::small_order::SMALL_ORDER_SIGS;
use crate::ed_sigs::{
    Signature, SigningKey, VerificationKey, VerificationKeyBytes,
    avx512::{
        CachedPublicKey, DalekVerifier, HotKeyCache, KeyCache, RuntimeVerifier,
        SIMD_MIN_BATCH_SIZE, VerifyInput, VerifyPolicy, Zip215Verifier,
    },
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

#[test]
fn scalar_fallback_matches_current_small_order_rules() {
    assert_eq!(SIMD_MIN_BATCH_SIZE, 2);

    let case = &SMALL_ORDER_SIGS[0];
    let inputs = [VerifyInput {
        public_key: case.vk_bytes,
        signature: case.sig_bytes,
        message: b"Zcash",
    }];

    let mut zip215 = Zip215Verifier::new();
    let mut zip215_out = [false];
    zip215.verify_batch(&inputs, &mut zip215_out);
    assert_eq!(zip215_out, [true]);

    let mut dalek = DalekVerifier::new();
    let mut dalek_out = [true];
    dalek.verify_batch(&inputs, &mut dalek_out);
    assert_eq!(dalek_out, [false]);
}

#[test]
fn simd_cutoff_and_runtime_facade_match_scalar_verification() {
    let cases: Vec<Case> = (0..SIMD_MIN_BATCH_SIZE as u8)
        .map(|index| {
            let mut seed = [0u8; 32];
            seed[0] = index;
            let signing_key = SigningKey::from(seed);
            let message = format!("AVX-512 cutoff case {index}").into_bytes();
            Case {
                public_key: VerificationKeyBytes::from(&signing_key).into(),
                signature: signing_key.sign(&message).into(),
                message,
            }
        })
        .collect();
    let inputs: Vec<VerifyInput<'_>> = cases
        .iter()
        .map(|case| VerifyInput {
            public_key: case.public_key,
            signature: case.signature,
            message: &case.message,
        })
        .collect();

    let mut zip215 = RuntimeVerifier::new();
    assert_eq!(zip215.policy(), VerifyPolicy::Zip215);
    let mut zip215_out = vec![false; inputs.len()];
    zip215.verify_batch(&inputs, &mut zip215_out);
    assert_eq!(zip215_out, expected(&inputs, false));

    let mut dalek = RuntimeVerifier::with_policy(VerifyPolicy::Dalek);
    assert_eq!(dalek.policy(), VerifyPolicy::Dalek);
    let mut dalek_out = vec![false; inputs.len()];
    dalek.verify_batch(&inputs, &mut dalek_out);
    assert_eq!(dalek_out, expected(&inputs, true));
}

#[test]
fn cached_singleton_refreshes_hot_key_recency() {
    let signing_keys: Vec<SigningKey> = (0..3u8)
        .map(|index| {
            let mut seed = [0u8; 32];
            seed[0] = index;
            SigningKey::from(seed)
        })
        .collect();
    let public_keys: Vec<[u8; 32]> = signing_keys
        .iter()
        .map(|key| VerificationKeyBytes::from(key).into())
        .collect();

    let mut cache = HotKeyCache::with_capacity(2);
    cache.insert(CachedPublicKey::from_encoded(public_keys[0]).expect("valid public key"));
    cache.insert(CachedPublicKey::from_encoded(public_keys[1]).expect("valid public key"));
    let mut verifier = Zip215Verifier::with_cache(cache);

    let inputs = [VerifyInput {
        public_key: public_keys[0],
        signature: signing_keys[0].sign(b"cached singleton").into(),
        message: b"cached singleton",
    }];
    let mut out = [false];
    verifier.verify_batch(&inputs, &mut out);
    assert_eq!(out, [true]);

    // Key 0 was the LRU before verification. Consulting the cache must make it
    // the MRU, so inserting key 2 evicts key 1 instead.
    verifier
        .cache_mut()
        .insert(CachedPublicKey::from_encoded(public_keys[2]).expect("valid public key"));
    assert!(verifier.cache().get(&public_keys[1]).is_none());
    assert!(verifier.cache().get(&public_keys[0]).is_some());
    assert!(verifier.cache().get(&public_keys[2]).is_some());
}
