//! Private wide Fq2 products with two Montgomery reductions.
//!
//! Lazy reduction of extension-field products follows Aranha et al., Section 3.1:
//! <https://eprint.iacr.org/2010/526>. Here only Fq2 multiplication is widened;
//! the BN254-specific bounds and negative-numerator correction are given below.
//!
//! With R=2^256 and q<2^254, every input to reduction is below qR.
//! These bounds do not relax the public canonical field-element contract.

use super::{adc, mac, sbb};
use crate::backend::{Field, Fq, Fq2, U256};

#[derive(Clone, Copy)]
struct Wide([u64; 8]);

impl Wide {
    #[inline]
    fn product(a: &U256, b: &U256) -> Self {
        let mut t = [0; 8];
        for i in 0..4 {
            let mut carry = 0;
            for j in 0..4 {
                (t[i + j], carry) = mac(t[i + j], a.0[i], b.0[j], carry);
            }
            t[i + 4] = carry;
        }
        Self(t)
    }

    #[inline]
    #[allow(clippy::needless_range_loop)] // Keep the audited limb/carry schedule explicit.
    fn sub(self, rhs: Self) -> (Self, u64) {
        let mut t = [0; 8];
        let mut borrow = 0;
        for i in 0..8 {
            (t[i], borrow) = sbb(self.0[i], rhs.0[i], borrow);
        }
        (Self(t), borrow)
    }

    // Requires 0<=self<qR. Classical REDC adds Mq with M<R, so its
    // quotient is below 2q<R and a single conditional subtraction suffices.
    #[inline]
    fn reduce(self) -> U256 {
        let mut t = [0; 9];
        t[..8].copy_from_slice(&self.0);
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
}

#[inline]
#[allow(clippy::needless_range_loop)] // Keep the audited limb/carry schedule explicit.
fn sum(a: &U256, b: &U256) -> U256 {
    let mut result = [0; 4];
    let mut carry = 0;
    for i in 0..4 {
        (result[i], carry) = adc(a.0[i], b.0[i], carry);
    }
    // Canonical inputs imply a+b<2q<R.
    debug_assert_eq!(carry, 0);
    U256::new(result)
}

#[inline]
pub(in crate::backend) fn mul(a: Fq2, b: Fq2) -> Fq2 {
    let real_product = Wide::product(&a.c0, &b.c0);
    let imaginary_product = Wide::product(&a.c1, &b.c1);
    let cross_product = Wide::product(&sum(&a.c0, &a.c1), &sum(&b.c0, &b.c1));
    // The imaginary numerator is a0*b1+a1*b0, in [0,2q²), below qR.
    let (cross, borrow) = cross_product.sub(real_product);
    debug_assert_eq!(borrow, 0);
    let (cross, borrow) = cross.sub(imaginary_product);
    debug_assert_eq!(borrow, 0);
    // The real numerator is in (-q²,q²). Add qR only when negative;
    // this leaves its Montgomery residue unchanged and yields [0,qR).
    let (mut real, borrow) = real_product.sub(imaginary_product);
    let mask = 0u64.wrapping_sub(borrow);
    let mut carry = 0;
    for i in 0..4 {
        (real.0[i + 4], carry) = adc(real.0[i + 4], Fq::MODULUS.0[i] & mask, carry);
    }
    // A negative wrapped difference plus qR carries beyond 512 bits.
    debug_assert_eq!(carry, borrow);
    Fq2 {
        c0: real.reduce(),
        c1: cross.reduce(),
    }
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
        let mut out = BigUint::from(0u8);
        for &limb in a.iter().rev() {
            out = (out << 64) + limb;
        }
        out
    }

    fn wide(a: &BigUint) -> Wide {
        let mut out = [0; 8];
        let limbs = a.to_u64_digits();
        assert!(limbs.len() <= 8);
        out[..limbs.len()].copy_from_slice(&limbs);
        Wide(out)
    }

    #[test]
    fn reduction_and_products_match_integer_oracle() {
        let q = integer(&Fq::MODULUS.0);
        let r = BigUint::from(1u8) << 256usize;
        let qr = &q * &r;
        let inv = BigUint::from_bytes_le(
            &ArkFq::from(2u64)
                .pow([256])
                .inverse()
                .unwrap()
                .into_bigint()
                .to_bytes_le(),
        );
        let mut inputs = vec![
            BigUint::from(0u8),
            BigUint::from(1u8),
            &q - 1u8,
            q.clone(),
            &r - 1u8,
            r.clone(),
            &q * &q,
            &qr - 1u8,
        ];
        let mut rng = StdRng::seed_from_u64(0x6671_3277_6964_6531);
        for _ in 0..4096 {
            let a = U256::new(rng.random());
            let b = U256::new(rng.random());
            let product = Wide::product(&a, &b);
            assert_eq!(integer(&product.0), integer(&a.0) * integer(&b.0));
            inputs.push(integer(&product.0) % &qr);
        }
        for input in inputs {
            let result = wide(&input).reduce();
            assert_eq!(integer(&result.0), input * &inv % &q);
        }
    }
}
