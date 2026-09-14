use ark_ff::{BigInt, Field as _, PrimeField};
use light_poseidon::PoseidonParameters;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Field, Fr, U256};
use solana_bn254::poseidon::constants::*;
use solana_bn254::poseidon::{PoseidonConstants, hash, poseidon};

type ArkFr = ark_bn254::Fr;

/// Compute all coordinates using unoptimized parameters and arkworks arithmetic.
fn reference_permutation<const T: usize>(
    mut state: [ArkFr; T],
    params: &PoseidonParameters<ArkFr>,
) -> [ArkFr; T] {
    let half_full = params.full_rounds / 2;
    for round in 0..params.full_rounds + params.partial_rounds {
        for (i, value) in state.iter_mut().enumerate() {
            *value += params.ark[round * T + i];
            if i == 0 || round < half_full || round >= half_full + params.partial_rounds {
                *value = value.pow([params.alpha]);
            }
        }
        state =
            core::array::from_fn(|i| state.iter().zip(&params.mds[i]).map(|(x, m)| *x * m).sum());
    }
    state
}

fn montgomery(value: ArkFr) -> U256 {
    let radix = ArkFr::from(2u64).pow([256u64]);
    U256::new((value * radix).into_bigint().0)
}

fn seeded_value(rng: &mut StdRng) -> ArkFr {
    ArkFr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>())
}

fn check_full_permutation<const T: usize>(constants: &PoseidonConstants<T>) {
    let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters(T as u8).unwrap();
    let r_inverse = ArkFr::from(2u64).pow([256u64]).inverse().unwrap();
    let mut rng = StdRng::seed_from_u64(0x6675_6c6c_7374_6174 ^ T as u64);
    for case in 0..12 {
        let state: [ArkFr; T] = core::array::from_fn(|i| match case {
            0 => ArkFr::from(0u64),
            1 => ArkFr::from((i + 1) as u64),
            2 => -ArkFr::from(1u64),
            3 => {
                // Raw residues just below p exercise the Montgomery boundary.
                let mut raw = <Fr as Field>::MODULUS.0;
                raw[0] -= (i + 1) as u64;
                ArkFr::from_bigint(BigInt(raw)).unwrap() * r_inverse
            }
            _ => seeded_value(&mut rng),
        });
        let expected = reference_permutation(state, &params).map(montgomery);
        assert_eq!(
            poseidon(state.map(montgomery), constants),
            expected,
            "width {T}, case {case}"
        );
    }
}

/// Two full rounds isolate the pre-sparse and final dense matrices. All
/// expected arithmetic and Montgomery conversions use arkworks.
fn check_custom_matrices<const T: usize>() {
    let radix = ArkFr::from(2u64).pow([256u64]);
    let to_raw = |v: ArkFr| U256::new((v * radix).into_bigint().0);
    let mds: [[ArkFr; T]; T] =
        core::array::from_fn(|i| core::array::from_fn(|j| -ArkFr::from((i * T + j + 1) as u64)));
    let pre_sparse: [[ArkFr; T]; T] =
        core::array::from_fn(|i| core::array::from_fn(|j| ArkFr::from((i + 3 * j + 2) as u64)));
    let rc: Vec<ArkFr> = (1..=2 * T).map(|i| ArkFr::from(i as u64)).collect();
    // The public parameter type requires static references. Allocate each
    // custom table once per width so it can be used through that same API.
    let constants = PoseidonConstants {
        full_rounds: 2,
        partial_rounds: 0,
        round_constants: Box::leak(
            rc.iter()
                .copied()
                .map(to_raw)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        mds_matrix: Box::leak(Box::new(mds.map(|row| row.map(to_raw)))),
        pre_sparse_matrix: Box::leak(Box::new(pre_sparse.map(|row| row.map(to_raw)))),
        sparse_matrices: &[],
    };
    let mut rng = StdRng::seed_from_u64(0x6d61_7472_6978_7631 ^ T as u64);
    for case in 0..12 {
        let mut state: [ArkFr; T] = core::array::from_fn(|i| match case {
            0 => ArkFr::from(0u64),
            1 => ArkFr::from((i + 1) as u64),
            2 => -ArkFr::from(1u64),
            _ => seeded_value(&mut rng),
        });
        state[0] = ArkFr::from(0u64);
        let mut expected = state;
        for (round, matrix) in [&pre_sparse, &mds].into_iter().enumerate() {
            for (i, value) in expected.iter_mut().enumerate() {
                *value = (*value + rc[round * T + i]).pow([5u64]);
            }
            expected = core::array::from_fn(|i| {
                expected.iter().zip(&matrix[i]).map(|(x, m)| *x * m).sum()
            });
        }
        let state = state.map(to_raw);
        let expected = expected.map(to_raw);
        assert_eq!(
            poseidon(state, &constants),
            expected,
            "width {T}, case {case}"
        );
        assert_eq!(
            hash(&state[1..], &constants),
            Some(expected[0]),
            "width {T}, case {case}"
        );
    }
}

macro_rules! matrix_suite {
    ($name:ident, $t:literal, $params:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn full_permutation_matches_arkworks() {
                check_full_permutation(&$params);
            }

            #[test]
            fn custom_matrices_match_arkworks() {
                check_custom_matrices::<$t>();
            }
        }
    };
}

matrix_suite!(t2, 2, BN254_X5_T2);
matrix_suite!(t3, 3, BN254_X5_T3);
matrix_suite!(t4, 4, BN254_X5_T4);
matrix_suite!(t5, 5, BN254_X5_T5);
matrix_suite!(t6, 6, BN254_X5_T6);
matrix_suite!(t7, 7, BN254_X5_T7);
matrix_suite!(t8, 8, BN254_X5_T8);
matrix_suite!(t9, 9, BN254_X5_T9);
matrix_suite!(t10, 10, BN254_X5_T10);
matrix_suite!(t11, 11, BN254_X5_T11);
matrix_suite!(t12, 12, BN254_X5_T12);
matrix_suite!(t13, 13, BN254_X5_T13);

#[test]
fn custom_matrices_with_three_vector_chunks() {
    check_custom_matrices::<17>();
}
