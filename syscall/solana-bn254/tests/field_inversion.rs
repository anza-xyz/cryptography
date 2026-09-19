//! Montgomery inversion checked using independent Fermat exponentiation.
//!
//! For a raw input a, the expected raw output is a^(p-2) * R^2 mod p.
//! This deliberately avoids using a binary-GCD inversion as the oracle.

use ark_bn254::{Fq as ArkFq, Fr as ArkFr};
use ark_ff::{BigInt, BigInteger, Fp256, MontBackend, MontConfig, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Field, Fq, Fr, MontgomeryBackend, U256};

#[derive(MontConfig)]
#[modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663"]
#[generator = "3"]
struct FullWidthConfig;

type ArkFullWidth = Fp256<MontBackend<FullWidthConfig, 4>>;
struct FullWidth;

impl Field for FullWidth {
    const MODULUS: U256 = U256::new(<FullWidthConfig as MontConfig<4>>::MODULUS.0);
    const INV: u64 = <FullWidthConfig as MontConfig<4>>::INV;
    const R2: U256 = U256::new(<FullWidthConfig as MontConfig<4>>::R2.0);
}

struct Oracle<P: PrimeField<BigInt = BigInt<4>>> {
    r: P,
    r2: P,
    exponent: BigInt<4>,
}

impl<P: PrimeField<BigInt = BigInt<4>>> Oracle<P> {
    fn new() -> Self {
        let r = P::from(2u64).pow([256u64]);
        let mut exponent = P::MODULUS;
        assert!(!exponent.sub_with_borrow(&BigInt::from(2u64)));
        Self {
            r,
            r2: r.square(),
            exponent,
        }
    }

    fn check<F: Field>(&self, a: U256) -> Option<U256> {
        assert_eq!(F::MODULUS.0, P::MODULUS.0);
        let x = P::from_bigint(BigInt(a.0)).unwrap();
        let expected = if x == P::ZERO {
            None
        } else {
            Some(U256::new((x.pow(self.exponent) * self.r2).into_bigint().0))
        };
        let actual = Backend::<F>::inv(&a);
        assert_eq!(actual, expected, "raw input={a:?}");
        if let Some(inverse) = actual {
            assert_eq!(
                Backend::<F>::mul(&a, &inverse),
                U256::new(self.r.into_bigint().0)
            );
            assert_eq!(Backend::<F>::inv(&inverse), Some(a));
        }
        actual
    }
}

fn check_boundaries<F: Field, P: PrimeField<BigInt = BigInt<4>>>() {
    let oracle = Oracle::<P>::new();
    oracle.check::<F>(U256::zero());
    oracle.check::<F>(U256::one());
    oracle.check::<F>(U256::new(oracle.r.into_bigint().0));
    oracle.check::<F>(F::R2);
    for delta in [1u64, 2, 3, 4, 7, 8, 16, 256, 65_536, u64::MAX] {
        oracle.check::<F>(U256::new((-P::from(delta)).into_bigint().0));
    }
    for bit in 0..P::MODULUS_BIT_SIZE as usize {
        let mut limbs = [0; 4];
        limbs[bit / 64] = 1 << (bit % 64);
        let power = P::from_bigint(BigInt(limbs)).unwrap();
        for value in [power - P::ONE, power, power + P::ONE] {
            oracle.check::<F>(U256::new(value.into_bigint().0));
        }
    }
}

fn check_seeded<F: Field, P: PrimeField<BigInt = BigInt<4>>>() {
    let oracle = Oracle::<P>::new();
    let mut rng = StdRng::seed_from_u64(0x696e_765f_6671_7631);
    for _ in 0..4096 {
        let value = P::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
        oracle.check::<F>(U256::new(value.into_bigint().0));
    }
}

#[test]
fn fq_boundaries_match_fermat() {
    check_boundaries::<Fq, ArkFq>();
}

#[test]
fn fq_seeded_inputs_match_fermat() {
    check_seeded::<Fq, ArkFq>();
}

#[test]
fn fr_boundaries_match_fermat() {
    check_boundaries::<Fr, ArkFr>();
}

#[test]
fn fr_seeded_inputs_match_fermat() {
    check_seeded::<Fr, ArkFr>();
}

#[test]
fn full_width_boundaries_match_fermat() {
    // This prime has no spare bit: signed coefficient updates must retain
    // the high limb until their result has been canonicalized.
    check_boundaries::<FullWidth, ArkFullWidth>();
}

#[test]
fn full_width_seeded_inputs_match_fermat() {
    check_seeded::<FullWidth, ArkFullWidth>();
}

#[test]
fn fq_inverse_chains_match_fermat() {
    let oracle = Oracle::<ArkFq>::new();
    let mut rng = StdRng::seed_from_u64(0x696e_765f_6368_6169);
    for _ in 0..64 {
        let start = ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
        let mut actual = U256::new(start.into_bigint().0);
        for _ in 0..32 {
            // Different addends avoid a degenerate alternating a, a^-1 chain.
            let addend = ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
            let expected_sum = ArkFq::from_bigint(BigInt(actual.0)).unwrap() + addend;
            actual = Backend::<Fq>::add(&actual, &U256::new(addend.into_bigint().0));
            assert_eq!(actual, U256::new(expected_sum.into_bigint().0));
            actual = oracle.check::<Fq>(actual).unwrap_or(U256::zero());
        }
    }
}
