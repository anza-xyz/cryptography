//! Direct tests for reduced scalar addition, checked against arkworks.
//!
//! Inputs and outputs are compared as raw canonical integers. Addition has
//! the same modular operation on Montgomery residues, so no backend
//! conversion routine is used by the oracle.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInt, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Fr, MontgomeryBackend, U256};

type B = Backend<Fr>;

fn from_ark(value: ArkFr) -> U256 {
    U256::new(value.into_bigint().0)
}

fn as_ark(value: &U256) -> ArkFr {
    ArkFr::from_bigint(BigInt::<4>(value.0)).expect("test input must be reduced")
}

fn random_element(rng: &mut StdRng) -> U256 {
    from_ark(ArkFr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>()))
}

fn check_add(a: &U256, b: &U256) {
    let expected = from_ark(as_ark(a) + as_ark(b));
    let actual = B::add(a, b);
    assert_eq!(actual, expected, "a={a:?}, b={b:?}");
}

#[test]
fn add_boundary_values_match_arkworks() {
    let one = ArkFr::from(1u64);
    let mut values = vec![ArkFr::from(0u64), one, ArkFr::from(2u64), ArkFr::from(3u64)];

    // Values near the modulus exercise the final conditional subtraction.
    for delta in [1u64, 2, 3, 4, 7, 8, 15, 16, u64::MAX] {
        values.push(-ArkFr::from(delta));
    }

    // Powers of two and their neighbors exercise carries across limb boundaries.
    for bit in [1usize, 63, 64, 65, 127, 128, 129, 191, 192, 193, 252, 253] {
        let mut limbs = [0u64; 4];
        limbs[bit / 64] = 1u64 << (bit % 64);
        let power = ArkFr::from_bigint(BigInt::<4>(limbs))
            .expect("boundary power must be below the modulus");
        values.extend([power - one, power, power + one]);
    }

    let values: Vec<U256> = values.into_iter().map(from_ark).collect();

    for a in &values {
        for b in &values {
            check_add(a, b);
        }
    }
}

#[test]
fn add_seeded_inputs_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6164_645f_7061_6972);

    for _ in 0..4096 {
        let a = random_element(&mut rng);
        let b = random_element(&mut rng);
        check_add(&a, &b);
    }
}

#[test]
fn add_chains_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6164_645f_6368_6169);

    for chain in 0..64 {
        let mut actual = random_element(&mut rng);
        let mut expected = as_ark(&actual);

        for step in 0..64 {
            let addend = random_element(&mut rng);
            actual = B::add(&actual, &addend);
            expected += as_ark(&addend);

            assert_eq!(
                actual,
                from_ark(expected),
                "chain={chain}, step={step}, addend={addend:?}"
            );
        }
    }
}
