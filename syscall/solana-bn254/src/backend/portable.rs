//! Pure Rust multi-limb arithmetic fallback.
//!
//! Provides a `MontgomeryBackend` using 64-bit limb arithmetic
//! without assuming x86_64 intrinsics.

use super::{Field, MontgomeryBackend, U256};
use core::marker::PhantomData;

/// Computes `a + b + carry`, returning `(result, carry_out)`.
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let res = (a as u128) + (b as u128) + (carry as u128);
    (res as u64, (res >> 64) as u64)
}

/// Computes `a - b - borrow`, returning `(result, borrow_out)`.
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (r1, b1) = a.overflowing_sub(b);
    let (r2, b2) = r1.overflowing_sub(borrow);
    (r2, (b1 as u64) | (b2 as u64))
}

/// Computes `a + (b * c) + carry`, returning `(result, carry_out)`.
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let res = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (res as u64, (res >> 64) as u64)
}

/// A portable, pure-Rust backend for Montgomery arithmetic.
pub struct PortableBackend<F: Field>(PhantomData<F>);

impl<F: Field> MontgomeryBackend<F> for PortableBackend<F> {
    #[inline(always)]
    fn add(a: &U256, b: &U256) -> U256 {
        let (r0, c) = adc(a.0[0], b.0[0], 0);
        let (r1, c) = adc(a.0[1], b.0[1], c);
        let (r2, c) = adc(a.0[2], b.0[2], c);
        let (r3, c) = adc(a.0[3], b.0[3], c);

        let (d0, br) = sbb(r0, F::MODULUS.0[0], 0);
        let (d1, br) = sbb(r1, F::MODULUS.0[1], br);
        let (d2, br) = sbb(r2, F::MODULUS.0[2], br);
        let (d3, br) = sbb(r3, F::MODULUS.0[3], br);

        // If no carry out and subtraction underflowed, a + b < MODULUS.
        if c == 0 && br == 1 {
            U256::new([r0, r1, r2, r3])
        } else {
            U256::new([d0, d1, d2, d3])
        }
    }

    #[inline(always)]
    fn sub(a: &U256, b: &U256) -> U256 {
        let (r0, br) = sbb(a.0[0], b.0[0], 0);
        let (r1, br) = sbb(a.0[1], b.0[1], br);
        let (r2, br) = sbb(a.0[2], b.0[2], br);
        let (r3, br) = sbb(a.0[3], b.0[3], br);

        if br > 0 {
            // Underflow occurred, add the modulus back to wrap around.
            let (d0, c) = adc(r0, F::MODULUS.0[0], 0);
            let (d1, c) = adc(r1, F::MODULUS.0[1], c);
            let (d2, c) = adc(r2, F::MODULUS.0[2], c);
            let (d3, _) = adc(r3, F::MODULUS.0[3], c);
            U256::new([d0, d1, d2, d3])
        } else {
            U256::new([r0, r1, r2, r3])
        }
    }

    #[inline(always)]
    fn mul(a: &U256, b: &U256) -> U256 {
        let mut t = [0u64; 5];

        for i in 0..4 {
            let (r0, c) = mac(t[0], a.0[i], b.0[0], 0);
            let (r1, c) = mac(t[1], a.0[i], b.0[1], c);
            let (r2, c) = mac(t[2], a.0[i], b.0[2], c);
            let (r3, c) = mac(t[3], a.0[i], b.0[3], c);
            let (r4, r5) = adc(t[4], 0, c);

            let m = r0.wrapping_mul(F::INV);

            let (_, c2) = mac(r0, m, F::MODULUS.0[0], 0);
            let (n0, c2) = mac(r1, m, F::MODULUS.0[1], c2);
            let (n1, c2) = mac(r2, m, F::MODULUS.0[2], c2);
            let (n2, c2) = mac(r3, m, F::MODULUS.0[3], c2);
            let (n3, c2) = adc(r4, 0, c2);

            t[0] = n0;
            t[1] = n1;
            t[2] = n2;
            t[3] = n3;
            t[4] = r5 + c2; // Overflow impossible here
        }

        let (d0, br) = sbb(t[0], F::MODULUS.0[0], 0);
        let (d1, br) = sbb(t[1], F::MODULUS.0[1], br);
        let (d2, br) = sbb(t[2], F::MODULUS.0[2], br);
        let (d3, br) = sbb(t[3], F::MODULUS.0[3], br);

        if t[4] == 0 && br == 1 {
            U256::new([t[0], t[1], t[2], t[3]])
        } else {
            U256::new([d0, d1, d2, d3])
        }
    }

    #[inline(always)]
    fn sqr(a: &U256) -> U256 {
        Self::mul(a, a)
    }

    #[inline(always)]
    fn neg(a: &U256) -> U256 {
        if a.0[0] == 0 && a.0[1] == 0 && a.0[2] == 0 && a.0[3] == 0 {
            *a
        } else {
            let (d0, br) = sbb(F::MODULUS.0[0], a.0[0], 0);
            let (d1, br) = sbb(F::MODULUS.0[1], a.0[1], br);
            let (d2, br) = sbb(F::MODULUS.0[2], a.0[2], br);
            let (d3, _) = sbb(F::MODULUS.0[3], a.0[3], br);
            U256::new([d0, d1, d2, d3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Fr;

    type B = PortableBackend<Fr>;

    /// `INV` must satisfy `INV * MODULUS == -1 (mod 2^64)`. Catches a
    /// transcription error in the Fr parameters that would otherwise only
    /// show up as silently wrong reductions.
    #[test]
    fn test_inv_parameter() {
        assert_eq!(Fr::INV.wrapping_mul(Fr::MODULUS.0[0]), u64::MAX);
    }

    /// `to_mont(1)` must equal `R mod r` for `R = 2^256`. This pins the
    /// Montgomery domain of the scalar backend, so a radix change cannot
    /// pass silently.
    #[test]
    fn test_montgomery_domain() {
        assert_eq!(
            B::to_mont(&U256::one()),
            U256::new([
                0xac96341c4ffffffb,
                0x36fc76959f60cd29,
                0x666ea36f7879462e,
                0x0e0a77c19a07df2f,
            ])
        );
    }

    #[test]
    fn test_addition() {
        let a = B::to_mont(&U256::new([1, 0, 0, 0]));
        let b = B::to_mont(&U256::new([2, 0, 0, 0]));
        let c = B::add(&a, &b);
        assert_eq!(B::from_mont(&c), U256::new([3, 0, 0, 0]));
    }

    #[test]
    fn test_subtraction() {
        let a = B::to_mont(&U256::new([5, 0, 0, 0]));
        let b = B::to_mont(&U256::new([3, 0, 0, 0]));
        let c = B::sub(&a, &b);
        assert_eq!(B::from_mont(&c), U256::new([2, 0, 0, 0]));

        let underflow = B::sub(&b, &a); // 3 - 5 mod MODULUS
        let mut expected = Fr::MODULUS;
        expected.0[0] -= 2;
        assert_eq!(B::from_mont(&underflow), expected);
    }

    #[test]
    fn test_multiplication() {
        let a = B::to_mont(&U256::new([100, 0, 0, 0]));
        let b = B::to_mont(&U256::new([200, 0, 0, 0]));
        let c = B::mul(&a, &b);
        assert_eq!(B::from_mont(&c), U256::new([20000, 0, 0, 0]));
    }

    #[test]
    fn test_negation() {
        let a = B::to_mont(&U256::new([12345, 0, 0, 0]));
        let neg_a = B::neg(&a);
        let sum = B::add(&a, &neg_a);
        assert_eq!(B::from_mont(&sum), U256::zero());
    }
}
