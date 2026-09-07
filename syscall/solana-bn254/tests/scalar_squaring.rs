//! Direct tests for scalar Montgomery squaring over BN254 Fr.
//!
//! Inputs are raw reduced Montgomery residues. The independent reference
//! treats those limbs as an integer a and computes a^2 * R^-1 mod p,
//! where R = 2^256. It does not use this crate's domain conversions.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInt, Field as _, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Fr, MontgomeryBackend, U256, portable::PortableBackend};

type B = PortableBackend<Fr>;

fn radix_inverse() -> ArkFr {
    ArkFr::from(2u64).pow([256u64]).inverse().unwrap()
}

fn random_raw(rng: &mut StdRng) -> U256 {
    let value = ArkFr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
    U256::new(value.into_bigint().0)
}

fn check_square(input: U256, r_inv: ArkFr) -> U256 {
    let integer =
        ArkFr::from_bigint(BigInt(input.0)).expect("test input must be below the Fr modulus");

    let expected = U256::new((integer.square() * r_inv).into_bigint().0);
    let actual = B::sqr(&input);

    // Exact limb equality also checks that the output is fully reduced.
    assert_eq!(
        actual, expected,
        "incorrect Montgomery square for input {input:?}"
    );

    actual
}

fn boundary_values() -> Vec<U256> {
    let modulus = ArkFr::MODULUS.0;

    let mut values = vec![
        U256::zero(),
        U256::one(),
        U256::new([u64::MAX, u64::MAX, u64::MAX, 0]),
        U256::new([u64::MAX, u64::MAX, u64::MAX, modulus[3] - 1]),
        U256::new([
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x1555_5555_5555_5555,
        ]),
        U256::new([
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0x2aaa_aaaa_aaaa_aaaa,
        ]),
    ];

    // Include the Montgomery representation of one.
    let montgomery_one = ArkFr::from(2u64).pow([256u64]);
    values.push(U256::new(montgomery_one.into_bigint().0));

    // These offsets fit within the low limb of the Fr modulus.
    for delta in [1u64, 2, 3, 4, 8, 16, 256, 65_536] {
        let mut limbs = modulus;
        limbs[0] -= delta;
        values.push(U256::new(limbs));
    }

    // Powers of two and their neighbors exercise sparse inputs and
    // carry patterns around every bit boundary, including limb boundaries.
    // The largest power below the Fr modulus is 2^253.
    for bit in 0..254usize {
        let mut limbs = [0u64; 4];
        limbs[bit / 64] = 1u64 << (bit % 64);

        let power = ArkFr::from_bigint(BigInt(limbs)).unwrap();
        let one = ArkFr::from(1u64);

        for value in [power - one, power, power + one] {
            values.push(U256::new(value.into_bigint().0));
        }
    }

    values
}

#[test]
fn square_boundary_values_match_arkworks() {
    let r_inv = radix_inverse();

    for input in boundary_values() {
        check_square(input, r_inv);
    }
}

#[test]
fn square_seeded_inputs_match_arkworks() {
    let r_inv = radix_inverse();
    let mut rng = StdRng::seed_from_u64(0x7371_7561_7265_0001);

    for _ in 0..4096 {
        check_square(random_raw(&mut rng), r_inv);
    }
}

#[test]
fn repeated_squaring_matches_arkworks() {
    let r_inv = radix_inverse();
    let mut rng = StdRng::seed_from_u64(0x7371_7561_7265_0002);

    for _ in 0..64 {
        let mut value = random_raw(&mut rng);

        for _ in 0..32 {
            value = check_square(value, r_inv);
        }
    }
}
