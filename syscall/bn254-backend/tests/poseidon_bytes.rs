//! Byte interface tests against light-poseidon, which `solana-poseidon` uses
//! for the `sol_poseidon` syscall today.
//!
//! The syscall reports every hashing error with the same return value, so the
//! digest and the set of rejected inputs are what must match.

use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254_backend::poseidon::{hash_be_bytes, hash_le_bytes};

/// This crate's digest and light-poseidon's, with `None` for an error.
fn hash_both(inputs: &[&[u8]], big_endian: bool) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
    let ours = if big_endian {
        hash_be_bytes(inputs)
    } else {
        hash_le_bytes(inputs)
    };
    // `solana-poseidon` builds the hasher for each call, so an unsupported
    // input count fails here.
    let theirs = Poseidon::<ark_bn254::Fr>::new_circom(inputs.len())
        .and_then(|mut hasher| {
            if big_endian {
                hasher.hash_bytes_be(inputs)
            } else {
                hasher.hash_bytes_le(inputs)
            }
        })
        .ok();
    (ours, theirs)
}

fn encode(value: ark_bn254::Fr, big_endian: bool) -> [u8; 32] {
    let bigint = value.into_bigint();
    let bytes = if big_endian {
        bigint.to_bytes_be()
    } else {
        bigint.to_bytes_le()
    };
    bytes.try_into().unwrap()
}

fn assert_rejected(inputs: &[&[u8]], big_endian: bool) {
    assert_eq!(hash_both(inputs, big_endian), (None, None));
}

#[test]
fn matches_light_poseidon() {
    let mut rng = StdRng::seed_from_u64(0x6279_7465_7368_6173);
    for count in 1..=12 {
        for case in 0..10 {
            let values: Vec<ark_bn254::Fr> = (0..count)
                .map(|i| match (case, i % 2) {
                    (0, _) => ark_bn254::Fr::ZERO,
                    (1, _) => -ark_bn254::Fr::ONE,
                    (2, 0) => ark_bn254::Fr::ZERO,
                    (2, _) => -ark_bn254::Fr::ONE,
                    _ => ark_bn254::Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()),
                })
                .collect();
            for big_endian in [false, true] {
                let encoded: Vec<[u8; 32]> =
                    values.iter().map(|v| encode(*v, big_endian)).collect();
                let inputs: Vec<&[u8]> = encoded.iter().map(|b| b.as_slice()).collect();
                let (ours, theirs) = hash_both(&inputs, big_endian);
                assert!(ours.is_some(), "count {count}, case {case}");
                assert_eq!(ours, theirs, "count {count}, case {case}");
            }
        }
    }
}

#[test]
fn rejects_unsupported_input_counts() {
    let input = [0u8; 32];
    for big_endian in [false, true] {
        assert_rejected(&[], big_endian);
        assert_rejected(&[input.as_slice(); 13], big_endian);
    }
}

#[test]
fn rejects_inputs_that_are_not_32_bytes() {
    let valid = [0u8; 32];
    let long = [0u8; 64];
    for length in [0, 1, 31, 33, 64] {
        for position in 0..3 {
            let mut inputs: [&[u8]; 3] = [&valid; 3];
            inputs[position] = &long[..length];
            for big_endian in [false, true] {
                assert_rejected(&inputs, big_endian);
            }
        }
    }
}

#[test]
fn rejects_inputs_not_below_the_modulus() {
    let modulus = ark_bn254::Fr::MODULUS;
    let mut modulus_plus_one = modulus;
    modulus_plus_one.add_with_carry(&1u64.into());
    let valid = [0u8; 32];
    for big_endian in [false, true] {
        let mut unreduced: Vec<[u8; 32]> = [modulus, modulus_plus_one]
            .iter()
            .map(|v| {
                let bytes = if big_endian {
                    v.to_bytes_be()
                } else {
                    v.to_bytes_le()
                };
                bytes.try_into().unwrap()
            })
            .collect();
        unreduced.push([0xff; 32]);
        for value in &unreduced {
            for position in 0..3 {
                let mut inputs: [&[u8]; 3] = [&valid; 3];
                inputs[position] = value;
                assert_rejected(&inputs, big_endian);
            }
        }
    }
}
