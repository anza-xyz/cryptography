//! Direct checks of scalar Montgomery multiplication against arkworks.
//!
//! Inputs are raw, reduced integers. Expected outputs are a * b * R^-1
//! modulo the scalar field modulus, where R = 2^256.
//!
//! Neither input construction nor reference calculations use the backend's
//! Montgomery conversion functions.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInt, Field, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Fr, MontgomeryBackend, U256};

type B = Backend<Fr>;

fn from_ark(value: ArkFr) -> U256 {
    U256::new(value.into_bigint().0)
}

fn as_ark_integer(value: &U256) -> ArkFr {
    ArkFr::from_bigint(BigInt::<4>(value.0))
        .expect("test operand must be smaller than the scalar field modulus")
}

fn montgomery_r_inverse() -> ArkFr {
    ArkFr::from(2u64)
        .pow([256u64])
        .inverse()
        .expect("R must be invertible modulo the scalar field modulus")
}

fn random_operand(rng: &mut StdRng) -> U256 {
    let bytes = rng.random::<[u8; 32]>();
    from_ark(ArkFr::from_le_bytes_mod_order(&bytes))
}

fn assert_product(a: &U256, b: &U256, r_inverse: ArkFr) {
    let expected = from_ark(as_ark_integer(a) * as_ark_integer(b) * r_inverse);
    let actual = B::mul(a, b);

    // Compare raw limbs so an unreduced result cannot pass by being
    // normalized during conversion back into an arkworks field element.
    assert_eq!(actual, expected, "incorrect product for a={a:?}, b={b:?}");
}

fn boundary_operands() -> Vec<U256> {
    let mut values = vec![
        U256::zero(),
        U256::one(),
        U256::new([2, 0, 0, 0]),
        U256::new([3, 0, 0, 0]),
    ];

    // Values immediately below the modulus, including a subtraction
    // that borrows across the lowest limb.
    for delta in [1u64, 2, 3, 4, 7, 8, 15, 16, u64::MAX] {
        values.push(from_ark(-ArkFr::from(delta)));
    }

    // Values around limb boundaries exercise carry propagation through
    // one, two, and three lower limbs. Include the highest usable bits.
    let one = ArkFr::from(1u64);
    for bit in [1usize, 63, 64, 65, 127, 128, 129, 191, 192, 193, 252, 253] {
        let mut limbs = [0u64; 4];
        limbs[bit / 64] = 1u64 << (bit % 64);

        let power = as_ark_integer(&U256::new(limbs));
        values.push(from_ark(power - one));
        values.push(from_ark(power));
        values.push(from_ark(power + one));
    }

    values
}

#[test]
fn mul_boundary_values_match_arkworks() {
    let r_inverse = montgomery_r_inverse();
    let values = boundary_operands();

    for a in &values {
        for b in &values {
            assert_product(a, b, r_inverse);
        }
    }
}

#[test]
fn mul_seeded_inputs_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6d75_6c5f_7061_6972);
    let r_inverse = montgomery_r_inverse();

    for _ in 0..4096 {
        let a = random_operand(&mut rng);
        let b = random_operand(&mut rng);
        assert_product(&a, &b, r_inverse);
    }
}

#[test]
fn mul_chains_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6d75_6c5f_6368_6169);
    let r_inverse = montgomery_r_inverse();

    for chain in 0..64 {
        let mut actual = random_operand(&mut rng);
        let mut expected = as_ark_integer(&actual);

        for step in 0..64 {
            let factor = random_operand(&mut rng);

            actual = B::mul(&actual, &factor);
            expected *= as_ark_integer(&factor) * r_inverse;

            assert_eq!(
                actual,
                from_ark(expected),
                "incorrect product in chain {chain}, step {step}"
            );
        }
    }
}
