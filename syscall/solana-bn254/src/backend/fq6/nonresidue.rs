//! Bounded integer accumulation for multiplication by `xi = 9+u`.
//!
//! Inputs and outputs are canonical Montgomery residues with radix `2^256`.
//! Only the private five-limb accumulator is unreduced; it is below `10q`.

use crate::backend::{Field, Fq, Fq2, U256};

const Q: [u64; 4] = Fq::MODULUS.0;

// With B=2^252, q=3B+d and 0 <= d < B/32. These inequalities include
// all possible lower limbs, not just an approximation to the high limb.
const _: () = {
    assert!(Q[3] >= 0x3000_0000_0000_0000);
    assert!(Q[3] < 0x3080_0000_0000_0000);
};

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

/// Reduces an integer `0 <= value < 10q`, returning a canonical residue.
#[inline(always)]
fn reduce(value: [u64; 5]) -> U256 {
    // k=floor(value/(3B)), obtained from the top five bits. Since value<10q,
    // k<=10. Writing value=3kB+s, 0<=s<3B, gives value-kq=s-kd in (-q,q).
    // Thus a negative result needs exactly one add-back; no subtraction follows.
    let estimate = ((value[4] << 4) | (value[3] >> 60)) / 3;
    debug_assert!(estimate <= 10);
    let mut result = [0; 4];
    let mut carry = 0i128;
    for (i, limb) in result.iter_mut().enumerate() {
        // -10W <= wide < W, hence the signed carry is in -10..=0.
        let wide = value[i] as i128 - estimate as i128 * Q[i] as i128 + carry;
        *limb = wide as u64;
        carry = wide >> 64;
    }
    let sign = value[4] as i128 + carry;
    debug_assert!((-1..=0).contains(&sign));
    if sign < 0 {
        let mut carry = 0u128;
        for (i, limb) in result.iter_mut().enumerate() {
            let wide = *limb as u128 + Q[i] as u128 + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
        // The low limbs represented 2^256 + remainder before this add-back.
        debug_assert_eq!(carry, 1);
    }
    U256::new(result)
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

    #[test]
    fn reduction_matches_integer_oracle_at_quotient_and_carry_boundaries() {
        assert_eq!(Q, ArkFq::MODULUS.0);
        let q = integer(Fq::MODULUS);
        let limit = 10u8 * &q;
        let b = BigUint::from(1u8) << 252usize;
        let mut values = vec![BigUint::from(0u8), &limit - 1u8];
        for k in 1u8..=10 {
            for boundary in [k * &q, 3u8 * k * &b] {
                values.extend([&boundary - 1u8, boundary.clone(), &boundary + 1u8]);
            }
        }
        for bit in [
            63usize, 64, 127, 128, 191, 192, 251, 252, 253, 254, 255, 256,
        ] {
            let boundary = BigUint::from(1u8) << bit;
            values.extend([&boundary - 1u8, boundary.clone(), &boundary + 1u8]);
        }
        let mut rng = StdRng::seed_from_u64(0x7869_5f72_6564_7631);
        for _ in 0..4096 {
            values.push(BigUint::from_bytes_le(&rng.random::<[u8; 40]>()) % &limit);
        }
        for value in values.into_iter().filter(|v| v < &limit) {
            assert_eq!(reduce(wide(&value)), raw(&(&value % &q)), "{value}");
        }
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
