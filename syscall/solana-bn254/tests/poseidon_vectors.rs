//! Cross-library, known-answer, and layout tests for the Poseidon implementation.
//!
//! The known-answer vectors carry the cross-platform guarantee. The AVX-512 IFMA
//! path is selected at compile time, so a single binary cannot exercise both the
//! scalar and SIMD backends; CI must run this suite twice:
//!
//! ```bash
//! cargo test -p solana-bn254 --test poseidon_vectors
//! RUSTFLAGS="-C target-feature=+avx512f,+avx512ifma,+avx512dq" \
//!     cargo test -p solana-bn254 --test poseidon_vectors
//! ```
//!
//! `light_poseidon` is instantiated over `ark_bn254::Fr`, so the comparison
//! below doubles as the arkworks cross-check.

use ark_ff::PrimeField;
use light_poseidon::PoseidonHasher;
use rand::RngExt;
use solana_bn254::backend::{Backend, Field, Fr, MontgomeryBackend, U256};
use solana_bn254::poseidon::constants::*;
use solana_bn254::poseidon::{PoseidonConstants, hash, poseidon};

/// Canonical integer into Montgomery form.
fn into_mont(v: U256) -> U256 {
    Backend::<Fr>::to_mont(&v)
}

/// Montgomery form back to a canonical integer.
fn out_of_mont(v: U256) -> U256 {
    Backend::<Fr>::from_mont(&v)
}

fn from_ark(v: ark_bn254::Fr) -> U256 {
    U256::new(v.into_bigint().0)
}

/// A uniformly random field element, as both representations.
fn random_element() -> (ark_bn254::Fr, U256) {
    let mut rng = rand::rng();
    let f = ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>());
    (f, into_mont(from_ark(f)))
}

/// True when `v` is a fully reduced field element.
fn is_canonical(v: &U256) -> bool {
    let m = <Fr as Field>::MODULUS.0;
    for i in (0..4).rev() {
        if v.0[i] != m[i] {
            return v.0[i] < m[i];
        }
    }
    false
}

macro_rules! width_suite {
    ($name:ident, $t:literal, $params:ident, $kat_seq:expr, $kat_zero:expr) => {
        mod $name {
            use super::*;

            /// The permutation indexes `round_constants` linearly and panics on a
            /// short table; pin the layout the generator promises.
            #[test]
            fn constant_layout() {
                let params: &PoseidonConstants<$t> = &$params;
                assert_eq!(params.full_rounds, 8);
                assert_eq!(
                    params.round_constants.len(),
                    $t * params.full_rounds + params.partial_rounds
                );
                assert_eq!(params.sparse_matrices.len(), params.partial_rounds);
            }

            /// Cross-library check against light-poseidon's unoptimized
            /// implementation over the same parameters.
            #[test]
            fn matches_light_poseidon() {
                let params: &PoseidonConstants<$t> = &$params;
                let mut reference =
                    light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom($t - 1).unwrap();

                for _ in 0..8 {
                    let mut ark_inputs = Vec::with_capacity($t - 1);
                    let mut our_inputs = Vec::with_capacity($t - 1);
                    for _ in 0..($t - 1) {
                        let (f, u) = random_element();
                        ark_inputs.push(f);
                        our_inputs.push(u);
                    }

                    let expected = from_ark(reference.hash(&ark_inputs).unwrap());
                    let got = out_of_mont(hash(&our_inputs, params).unwrap());
                    assert_eq!(got, expected);
                }
            }

            /// Known-answer vectors, so this suite keeps its meaning if
            /// light-poseidon ever leaves the dev-dependencies, and so the
            /// scalar and SIMD builds are held to identical output.
            #[test]
            fn known_answer() {
                let params: &PoseidonConstants<$t> = &$params;

                let sequential: Vec<U256> = (1..$t as u64)
                    .map(|i| into_mont(U256::new([i, 0, 0, 0])))
                    .collect();
                assert_eq!(out_of_mont(hash(&sequential, params).unwrap()), $kat_seq);

                let zeros = [U256::zero(); $t - 1];
                assert_eq!(out_of_mont(hash(&zeros, params).unwrap()), $kat_zero);
            }

            /// Outputs must be fully reduced. An unreduced result still lands in
            /// the right residue class, so it would pass a mod-r comparison while
            /// serializing to different bytes than another build produces.
            #[test]
            fn output_is_canonical() {
                let params: &PoseidonConstants<$t> = &$params;
                let mut state = [U256::zero(); $t];
                for slot in state[1..].iter_mut() {
                    *slot = random_element().1;
                }
                for value in poseidon(state, params).iter() {
                    assert!(is_canonical(value), "unreduced output: {:?}", value);
                }
            }

            #[test]
            fn rejects_wrong_input_count() {
                let params: &PoseidonConstants<$t> = &$params;
                let too_many = [U256::zero(); $t];
                assert!(hash(&too_many, params).is_none());
            }
        }
    };
}

width_suite!(
    t2,
    2,
    BN254_X5_T2,
    U256::new([
        0x8b897dc502820133,
        0x0e96a4d1168b3384,
        0xc1fe6c654d6a3c13,
        0x29176100eaa962bd
    ]),
    U256::new([
        0x3aed2411cb65e11c,
        0xe8f7aa12e2b4940a,
        0x6b91effbb2499f07,
        0x2a09a9fd93c590c2
    ])
);
width_suite!(
    t3,
    3,
    BN254_X5_T3,
    U256::new([
        0x9e19607a4417189a,
        0x2a3617f274324551,
        0x3df64c6b9662e9cf,
        0x115cc0f5e7d69041
    ]),
    U256::new([
        0xa839ee8446b64864,
        0xdc3124d55ffed523,
        0x3ceac3f27b81e481,
        0x2098f5fb9e239eab
    ])
);
width_suite!(
    t4,
    4,
    BN254_X5_T4,
    U256::new([
        0xf725df34ab36d732,
        0xf3230e269dc5b968,
        0xff03d5e58dab6302,
        0x0e7732d89e6939c0
    ]),
    U256::new([
        0x7cee6db31ba599aa,
        0xe2864eecec96c5ae,
        0x1dcfb6af0a7af08f,
        0x0bc188d27dcceadc
    ])
);
width_suite!(
    t5,
    5,
    BN254_X5_T5,
    U256::new([
        0xbaa525df65250465,
        0x37e60ebb1ce0663d,
        0x9dcefa40e4510b98,
        0x299c867db6c1fdd7
    ]),
    U256::new([
        0x88c1206db73e9946,
        0x0937921b8b790604,
        0x51209694d9c21525,
        0x0532fd436e19c70e
    ])
);
width_suite!(
    t6,
    6,
    BN254_X5_T6,
    U256::new([
        0x18125f8feeb123c0,
        0x8b2174d305a316c9,
        0x15224c0b15a49d59,
        0x0dab9449e4a1398a
    ]),
    U256::new([
        0xe75e342b160a95bc,
        0x9118c62eabc42e2f,
        0x7e079360abe14fbf,
        0x2066be41bebe6caf
    ])
);
width_suite!(
    t7,
    7,
    BN254_X5_T7,
    U256::new([
        0x134a4cca2f6302e1,
        0x38490a68b05f2239,
        0x13c8ebf094dea475,
        0x2d1a038500844428
    ]),
    U256::new([
        0xb3482bb02eb353d5,
        0x86a4f442b8a073d5,
        0x2bec7084abc047ae,
        0x1fdb1d1757a3a350
    ])
);
width_suite!(
    t8,
    8,
    BN254_X5_T8,
    U256::new([
        0x2e9df45b4921c318,
        0x4a9a85fcfc6533ec,
        0xebb9ada49abdbc37,
        0x1c2f3482dbb140c4
    ]),
    U256::new([
        0xe49b362f73491a26,
        0xf03e8330219f8bf1,
        0x7d2598e4f93c389b,
        0x0a47ead74da5372e
    ])
);
width_suite!(
    t9,
    9,
    BN254_X5_T9,
    U256::new([
        0x4d43b3d8d0c4d8d1,
        0x337a4d54fbbecd9a,
        0x98e40395c0fefb40,
        0x2921ab9bd0140cbc
    ]),
    U256::new([
        0x4a4f5f653348622a,
        0xe04d6278d68d5293,
        0xc9b97d446bf7de69,
        0x035ebc384d320413
    ])
);
width_suite!(
    t10,
    10,
    BN254_X5_T10,
    U256::new([
        0x204af32e60cd9078,
        0x75b22bb3aaa4461d,
        0x75e749d260330b76,
        0x1e0b893aa2ad8022
    ]),
    U256::new([
        0x0a44ad86b2075728,
        0x033c11cc3bd113ef,
        0x4e1dc256d82ba808,
        0x01c4da168cbfb501
    ])
);
width_suite!(
    t11,
    11,
    BN254_X5_T11,
    U256::new([
        0x8db9ad07206fdc21,
        0x59816fc60d6738b7,
        0xcc0628461dacfb94,
        0x0816126a09c29ecf
    ]),
    U256::new([
        0x8a4850cc5e863a4f,
        0xb2bb4b352a5abdcf,
        0xe84638b1fd477962,
        0x121abf316742b318
    ])
);
width_suite!(
    t12,
    12,
    BN254_X5_T12,
    U256::new([
        0xdae0e07fc05b47a8,
        0x2429e211f71cacdb,
        0x8f30a6b785b6c5ae,
        0x07e5b070aa2dba00
    ]),
    U256::new([
        0x6198f3180d6d4d7f,
        0x9aa6de067dcffda1,
        0xc9c0cfeb9c8a1c1b,
        0x23376b08cad4f9a7
    ])
);
width_suite!(
    t13,
    13,
    BN254_X5_T13,
    U256::new([
        0x94e856c1ef7693b5,
        0x681cc08702c81684,
        0xb248a01e7cc55b3d,
        0x058814945232937d
    ]),
    U256::new([
        0xeb39dafa33f48453,
        0xaa47e82e9b139396,
        0x8d677d97f02e5063,
        0x14b1efe6a1d69ba2
    ])
);
