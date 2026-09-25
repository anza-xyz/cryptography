//! Dedicated Fq integer square followed by Montgomery reduction.
//!
//! The symmetric-product saving is described in Handbook of Applied Cryptography,
//! Algorithm 14.16; this implementation accumulates by output column:
//! <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

use super::{adc, mac, sbb};
use crate::backend::{Field, Fq, U256};

// Dedicated integer squaring: ten distinct 64x64 products. Cross terms are
// accumulated twice through a 192-bit column accumulator, so doubling never
// relies on a 129-bit value fitting in u128. Each column has at most four terms;
// the third accumulator limb is at most a small carry count.
#[inline]
fn square_product(a: &U256) -> [u64; 8] {
    let mut result = [0; 8];
    let (mut low, mut middle, mut high) = (0u64, 0u64, 0u64);
    macro_rules! product {
        ($i:expr, $j:expr, $double:expr) => {{
            let p = u128::from(a.0[$i]) * u128::from(a.0[$j]);
            let p0 = p as u64;
            let p1 = (p >> 64) as u64;
            let mut carry;
            (low, carry) = adc(low, p0, 0);
            (middle, carry) = adc(middle, p1, carry);
            high += carry;
            if $double {
                (low, carry) = adc(low, p0, 0);
                (middle, carry) = adc(middle, p1, carry);
                high += carry;
            }
        }};
    }
    macro_rules! column {
        ($i:expr) => {{
            result[$i] = low;
            low = middle;
            middle = high;
            high = 0;
        }};
    }
    product!(0, 0, false);
    column!(0);
    product!(0, 1, true);
    column!(1);
    product!(0, 2, true);
    product!(1, 1, false);
    column!(2);
    product!(0, 3, true);
    product!(1, 2, true);
    column!(3);
    product!(1, 3, true);
    product!(2, 2, false);
    column!(4);
    product!(2, 3, true);
    column!(5);
    product!(3, 3, false);
    result[6] = low;
    low = middle;
    middle = high;
    result[7] = low;
    debug_assert_eq!(middle, 0);
    result
}

// Requires 0<=self<qR. Classical REDC adds Mq with M<R, so its
// quotient is below 2q<R and a single conditional subtraction suffices.
#[inline]
fn reduce(input: [u64; 8]) -> U256 {
    let mut t = [0; 9];
    t[..8].copy_from_slice(&input);
    for i in 0..4 {
        let m = t[i].wrapping_mul(Fq::INV);
        let mut carry = 0;
        for j in 0..4 {
            (t[i + j], carry) = mac(t[i + j], m, Fq::MODULUS.0[j], carry);
        }
        for limb in &mut t[i + 4..] {
            (*limb, carry) = adc(*limb, 0, carry);
        }
        debug_assert_eq!(carry, 0);
    }
    debug_assert_eq!(t[8], 0);
    let mut d = [0; 4];
    let mut borrow = 0;
    for i in 0..4 {
        (d[i], borrow) = sbb(t[i + 4], Fq::MODULUS.0[i], borrow);
    }
    let mask = 0u64.wrapping_sub(borrow);
    U256::new(core::array::from_fn(|i| (t[i + 4] & mask) | (d[i] & !mask)))
}

/// Canonical Fq input implies a²<q²<qR, the reducer's private range.
#[inline]
pub(super) fn square(a: &U256) -> U256 {
    reduce(square_product(a))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ark_bn254::Fq as ArkFq;
    use ark_ff::{BigInteger, Field as _, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::vec;

    fn integer(a: &[u64]) -> BigUint {
        a.iter()
            .rev()
            .fold(BigUint::from(0u8), |n, &v| (n << 64usize) + v)
    }
    fn limbs(a: &BigUint) -> U256 {
        let mut out = [0; 4];
        let digits = a.to_u64_digits();
        out[..digits.len()].copy_from_slice(&digits);
        U256::new(out)
    }
    #[test]
    fn dedicated_square_matches_full_width_integer_and_field_oracles() {
        let q = integer(&Fq::MODULUS.0);
        let inv = BigUint::from_bytes_le(
            &ArkFq::from(2u64)
                .pow([256])
                .inverse()
                .unwrap()
                .into_bigint()
                .to_bytes_le(),
        );
        let mut inputs = vec![
            U256::zero(),
            U256::new([1, 0, 0, 0]),
            U256::new([u64::MAX; 4]),
            limbs(&(&q - 1u8)),
            Fq::MODULUS,
        ];
        for bit in 0..256 {
            inputs.push(limbs(&(BigUint::from(1u8) << bit)));
        }
        let mut rng = StdRng::seed_from_u64(0x7371_7561_7265_6671);
        for _ in 0..4096 {
            inputs.push(U256::new(rng.random()));
        }
        for input in inputs {
            let raw = integer(&input.0);
            assert_eq!(integer(&square_product(&input)), &raw * &raw);
            let canonical = &raw % &q;
            let result = square(&limbs(&canonical));
            assert_eq!(integer(&result.0), &canonical * &canonical * &inv % &q);
        }
    }
}
