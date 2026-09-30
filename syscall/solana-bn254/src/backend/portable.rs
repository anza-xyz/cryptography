//! Multi-limb arithmetic with an optional native Fq multiplication kernel.
//!
//! Provides a `MontgomeryBackend` using 64-bit limb arithmetic
//! with a portable fallback on targets without Linux x86_64 ADX/BMI2.
//! The CIOS schedule follows Koc, Acar and Kaliski, Section 5:
//! <https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf>.

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

/// Adds `s * v + pending * 2^256` into `t[..5]`, returning the carry out of `t[4]`.
#[inline(always)]
fn mac_row(t: &mut [u64], s: u64, v: &U256, pending: u64) -> u64 {
    let mut carry = 0;
    for (tj, &vj) in t.iter_mut().zip(&v.0) {
        (*tj, carry) = mac(*tj, s, vj, carry);
    }
    let (top, carry_out) = adc(t[4], carry, pending);
    t[4] = top;
    carry_out
}

/// Montgomery arithmetic with a portable fallback and optional native Fq kernel.
pub struct PortableBackend<F: Field>(PhantomData<F>);

#[cfg(all(
    target_arch = "x86_64",
    target_os = "linux",
    target_feature = "adx",
    target_feature = "bmi2",
))]
mod adx;
mod fq2_sum;
pub(super) mod fq2_wide;
mod fq_reduction;
mod inversion;
pub(crate) mod small_multiple;
mod square;

pub(super) use fq2_sum::FqSum;

impl<F: Field> PortableBackend<F> {
    /// `LAZY_TERMS * MODULUS < 2^256` keeps a chunk sum below `MODULUS * 2^256`.
    pub(crate) const LAZY_TERMS: usize = {
        let terms = (1u128 << 64) / (F::MODULUS.0[3] as u128 + 1);
        if terms > usize::MAX as u128 {
            usize::MAX
        } else {
            terms as usize
        }
    };

    /// Inverts a canonical Montgomery residue, returning `None` for zero.
    ///
    /// For input `a = x * R mod p`, returns `x^-1 * R mod p`, fully reduced,
    /// where `R = 2^256`. As with the other backend operations, `a < p` is
    /// required. Execution is variable-time and intended for public data.
    pub fn inv(a: &U256) -> Option<U256> {
        inversion::invert::<F>(a)
    }

    // Private kernel: callers supply reduced operands, except FqSum, whose
    // separate proof permits Fq operands below 2q and retains canonical output.
    #[inline(always)]
    fn mul_cios(a: &U256, b: &U256) -> U256 {
        #[cfg(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_feature = "adx",
            target_feature = "bmi2",
        ))]
        if F::MODULUS == crate::backend::Fq::MODULUS {
            return adx::mul(a, b);
        }

        // Write p = MODULUS and W = 2^64. Each CIOS step is
        // t <- (t + a_i * b + m * p) / W, with a_i, m < W.
        // Starting at zero, this preserves t < b + p.
        // For reduced b and p < 2^255 (or FqSum), b + p < 2^256, so t[4]
        // stays zero and the final top-limb sum cannot overflow.
        let has_spare_bit = F::MODULUS.0[3] < (1u64 << 63);
        let mut t = [0u64; 5];

        for i in 0..4 {
            let (r0, c) = mac(t[0], a.0[i], b.0[0], 0);
            let (r1, c) = mac(t[1], a.0[i], b.0[1], c);
            let (r2, c) = mac(t[2], a.0[i], b.0[2], c);
            let (r3, c) = mac(t[3], a.0[i], b.0[3], c);
            let (r4, r5) = if has_spare_bit {
                (c, 0)
            } else {
                adc(t[4], 0, c)
            };

            let m = r0.wrapping_mul(F::INV);

            let (_, c2) = mac(r0, m, F::MODULUS.0[0], 0);
            let (n0, c2) = mac(r1, m, F::MODULUS.0[1], c2);
            let (n1, c2) = mac(r2, m, F::MODULUS.0[2], c2);
            let (n2, c2) = mac(r3, m, F::MODULUS.0[3], c2);
            let (n3, c2) = if has_spare_bit {
                (r4 + c2, 0)
            } else {
                adc(r4, 0, c2)
            };

            t[0] = n0;
            t[1] = n1;
            t[2] = n2;
            t[3] = n3;
            t[4] = r5 + c2; // Overflow impossible here
        }

        Self::reduce_once([t[0], t[1], t[2], t[3]], t[4])
    }

    // Fq curve callers keep `fq_reduction::reduce`, measured faster for them on x86_64.
    /// Maps `t < MODULUS * 2^256` to `t * R^-1 mod MODULUS`.
    #[inline(always)]
    fn montgomery_reduce(mut t: [u64; 8]) -> U256 {
        let mut pending = 0;
        for i in 0..4 {
            let m = t[i].wrapping_mul(F::INV);
            pending = mac_row(&mut t[i..], m, &F::MODULUS, pending);
        }
        Self::reduce_once([t[4], t[5], t[6], t[7]], pending)
    }

    /// Maps `x + hi * 2^256 < 2 * MODULUS` to `(x + hi * 2^256) mod MODULUS`.
    #[inline(always)]
    fn reduce_once(x: [u64; 4], hi: u64) -> U256 {
        let (d0, br) = sbb(x[0], F::MODULUS.0[0], 0);
        let (d1, br) = sbb(x[1], F::MODULUS.0[1], br);
        let (d2, br) = sbb(x[2], F::MODULUS.0[2], br);
        let (d3, br) = sbb(x[3], F::MODULUS.0[3], br);

        // If no carry out and subtraction underflowed, x < MODULUS.
        if hi == 0 && br == 1 {
            U256::new(x)
        } else {
            U256::new([d0, d1, d2, d3])
        }
    }
}

impl<F: Field> MontgomeryBackend<F> for PortableBackend<F> {
    #[inline(always)]
    fn add(a: &U256, b: &U256) -> U256 {
        let (r0, c) = adc(a.0[0], b.0[0], 0);
        let (r1, c) = adc(a.0[1], b.0[1], c);
        let (r2, c) = adc(a.0[2], b.0[2], c);
        // Reduced inputs satisfy a + b < 2 * MODULUS.
        // If MODULUS < 2^255, the sum fits in 256 bits, so the
        // top limb has no carry out.
        let (r3, c) = if F::MODULUS.0[3] < (1u64 << 63) {
            (a.0[3] + b.0[3] + c, 0)
        } else {
            adc(a.0[3], b.0[3], c)
        };

        Self::reduce_once([r0, r1, r2, r3], c)
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
        Self::mul_cios(a, b)
    }

    #[inline(always)]
    fn sqr(a: &U256) -> U256 {
        if F::MODULUS == crate::backend::Fq::MODULUS {
            square::square(a)
        } else {
            Self::mul(a, a)
        }
    }

    #[inline(always)]
    fn sum_of_products<const N: usize>(a: &[U256; N], b: &[U256; N]) -> U256 {
        let mut sum = None;
        for (k, a) in a.chunks(Self::LAZY_TERMS).enumerate() {
            let mut t = [0u64; 8];
            for (x, y) in a.iter().zip(&b[k * Self::LAZY_TERMS..]) {
                // A chunk sum stays below 2^512, so the last row carries nothing out.
                let mut pending = 0;
                for (i, &xi) in x.0.iter().enumerate() {
                    pending = mac_row(&mut t[i..], xi, y, pending);
                }
            }
            let chunk = Self::montgomery_reduce(t);
            sum = Some(match sum {
                Some(sum) => Self::add(&sum, &chunk),
                None => chunk,
            });
        }
        sum.unwrap_or_default()
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
