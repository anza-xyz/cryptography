//! Bounded integer accumulation for multiplication by `xi = 9+u`.
//!
//! Inputs and outputs are canonical Montgomery residues with radix `2^256`.
//! Only the private five-limb accumulator is unreduced; it is below `10q`.

use crate::backend::{Field, Fq, Fq2, U256, portable::small_multiple::reduce};

const Q: [u64; 4] = Fq::MODULUS.0;

/// Forms `9a+b` or `9a+q-b` from canonical coefficients, without reduction.
#[inline(always)]
fn accumulate<const SUBTRACT: bool>(a: &U256, b: &U256) -> [u64; 5] {
    let mut result = [0; 5];
    let mut carry = 0i128;
    for (i, limb) in result[..4].iter_mut().enumerate() {
        let adjustment = if SUBTRACT {
            Q[i] as i128 - b.0[i] as i128
        } else {
            b.0[i] as i128
        };
        // For W=2^64, -W <= wide <= 10W-1; the signed carry is in -1..=9.
        let wide = 9 * a.0[i] as i128 + adjustment + carry;
        *limb = wide as u64;
        carry = wide >> 64;
    }
    // 0 <= result < 10q < 2*2^256. No high bit is discarded.
    debug_assert!((0..=1).contains(&carry));
    result[4] = carry as u64;
    result
}

/// Multiplies a canonical Fq2 value by the cubic nonresidue `9+u`.
#[inline]
pub(crate) fn mul_by_xi(value: Fq2) -> Fq2 {
    Fq2 {
        c0: reduce(accumulate::<true>(&value.c0, &value.c1)),
        c1: reduce(accumulate::<false>(&value.c1, &value.c0)),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_bn254::Fq as ArkFq;
    use ark_ff::{BigInt, BigInteger, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::vec;

    fn integer(value: U256) -> BigUint {
        BigUint::from_bytes_le(&BigInt(value.0).to_bytes_le())
    }

    fn raw(value: &BigUint) -> U256 {
        let digits = value.to_u64_digits();
        assert!(digits.len() <= 4);
        let mut limbs = [0; 4];
        limbs[..digits.len()].copy_from_slice(&digits);
        U256::new(limbs)
    }

    fn wide(value: &BigUint) -> [u64; 5] {
        let digits = value.to_u64_digits();
        assert!(digits.len() <= 5);
        let mut limbs = [0; 5];
        limbs[..digits.len()].copy_from_slice(&digits);
        limbs
    }

    fn coefficient(rng: &mut StdRng, q: &BigUint) -> BigUint {
        integer(U256::new(rng.random())) % q
    }

    fn check(a: &BigUint, b: &BigUint, q: &BigUint) {
        let minus = 9u8 * a + q - b;
        let plus = 9u8 * b + a;
        let (a_raw, b_raw) = (raw(a), raw(b));
        assert_eq!(accumulate::<true>(&a_raw, &b_raw), wide(&minus));
        assert_eq!(accumulate::<false>(&b_raw, &a_raw), wide(&plus));
        let input = Fq2::from_montgomery(a_raw, b_raw).unwrap();
        assert_eq!(
            mul_by_xi(input).to_montgomery(),
            (raw(&(minus % q)), raw(&(plus % q)))
        );
    }

    #[test]
    fn nonresidue_matches_integer_oracle_for_boundaries_and_seeded_inputs() {
        assert_eq!(Q, ArkFq::MODULUS.0);
        let q = integer(Fq::MODULUS);
        let mut values = vec![BigUint::from(0u8), BigUint::from(1u8), &q - 1u8, &q - 2u8];
        for bit in [64usize, 128, 192, 253] {
            let power = BigUint::from(1u8) << bit;
            values.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        for k in 1u8..=9 {
            let boundary = k * &q / 9u8;
            values.extend([&boundary - 1u8, boundary.clone(), &boundary + 1u8]);
        }
        let carry_boundary = (BigUint::from(1u8) << 256usize) / 9u8;
        values.extend([
            &carry_boundary - 1u8,
            carry_boundary.clone(),
            &carry_boundary + 1u8,
        ]);
        values.retain(|v| v < &q);
        for a in &values {
            for b in &values {
                check(a, b, &q);
            }
        }
        let mut rng = StdRng::seed_from_u64(0x7869_5f6c_617a_7631);
        for _ in 0..4096 {
            check(&coefficient(&mut rng, &q), &coefficient(&mut rng, &q), &q);
        }
    }

    #[test]
    fn dependent_nonresidue_chains_match_integer_oracle() {
        let q = integer(Fq::MODULUS);
        let mut rng = StdRng::seed_from_u64(0x7869_5f63_686e_7631);
        for _ in 0..64 {
            let (mut a, mut b) = (coefficient(&mut rng, &q), coefficient(&mut rng, &q));
            let mut actual = Fq2::from_montgomery(raw(&a), raw(&b)).unwrap();
            for _ in 0..64 {
                let next_a = (9u8 * &a + &q - &b) % &q;
                let next_b = (9u8 * &b + &a) % &q;
                actual = mul_by_xi(actual);
                assert_eq!(actual.to_montgomery(), (raw(&next_a), raw(&next_b)));
                (a, b) = (next_a, next_b);
            }
        }
    }
}
