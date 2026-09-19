//! Private input sums for Fq2 products. Outputs are canonical Fq residues.

use super::{PortableBackend, adc};
use crate::backend::{Field, Fq, MontgomeryBackend, U256};

type B = PortableBackend<Fq>;

/// An unreduced Montgomery Fq operand below `2q`, with radix `R = 2^256`.
/// Construction from canonical coefficients gives the tighter bound `2q-2`.
pub(in crate::backend) struct FqSum(U256);

impl FqSum {
    /// Adds two canonical coefficients without the modular subtraction.
    #[inline(always)]
    pub(in crate::backend) fn new(a: &U256, b: &U256) -> Self {
        debug_assert!(B::is_reduced(a) && B::is_reduced(b));
        let (r0, c) = adc(a.0[0], b.0[0], 0);
        let (r1, c) = adc(a.0[1], b.0[1], c);
        let (r2, c) = adc(a.0[2], b.0[2], c);
        // a+b < 2q < 2^255, so the top limb cannot overflow.
        Self(U256::new([r0, r1, r2, a.0[3] + b.0[3] + c]))
    }

    /// Returns a canonical product, in the original Montgomery domain.
    #[inline(always)]
    pub(in crate::backend) fn product(self, rhs: Self) -> U256 {
        // q < 2^254, so 4q < R. For a,b < 2q, the CIOS invariant
        // t < b+q gives t < 3q < R, preserving the spare-bit carry path.
        // Finally t=(ab+Mq)/R, 0<=M<R, so t<4q^2/R+q<2q.
        // Thus one subtraction suffices, just as for reduced operands.
        B::mul_cios(&self.0, &rhs.0)
    }

    /// The same bound applies when the second operand is already canonical.
    #[inline(always)]
    pub(in crate::backend) fn product_reduced(self, rhs: &U256) -> U256 {
        debug_assert!(B::is_reduced(rhs));
        B::mul_cios(&self.0, rhs)
    }
}

// This is an Fq-specific bound, not a relaxed generic backend contract.
const _: () = assert!(Fq::MODULUS.0[3] < (1u64 << 62));

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_bn254::Fq as ArkFq;
    use ark_ff::{BigInteger, Field as _, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::vec;

    fn integer(value: &U256) -> BigUint {
        BigUint::from_bytes_le(&ark_ff::BigInt(value.0).to_bytes_le())
    }

    fn raw(value: &BigUint) -> U256 {
        let digits = value.to_u64_digits();
        assert!(digits.len() <= 4);
        let mut limbs = [0; 4];
        limbs[..digits.len()].copy_from_slice(&digits);
        U256::new(limbs)
    }

    fn check(a: &BigUint, b: &BigUint, q: &BigUint, r_inverse: &BigUint) {
        let expected = raw(&(a * b * r_inverse % q));
        assert_eq!(FqSum(raw(a)).product(FqSum(raw(b))), expected);
        if b < q {
            assert_eq!(FqSum(raw(a)).product_reduced(&raw(b)), expected);
        }
    }

    #[test]
    fn unreduced_sum_boundaries_match_integer_oracle() {
        let q = integer(&Fq::MODULUS);
        let mut values = vec![BigUint::from(0u8), BigUint::from(1u8), &q - 1u8, &q - 2u8];
        for bit in [64usize, 128, 192, 253] {
            let power = BigUint::from(1u8) << bit;
            values.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        for a in &values {
            for b in &values {
                let sum = FqSum::new(&raw(a), &raw(b));
                assert_eq!(integer(&sum.0), a + b);
                assert!(integer(&sum.0) < 2u8 * &q);
            }
        }
    }

    #[test]
    fn private_products_match_integer_oracle() {
        let q = integer(&Fq::MODULUS);
        let twice_q = 2u8 * &q;
        let r_inverse = integer(&U256::new(
            ArkFq::from(2u64)
                .pow([256])
                .inverse()
                .unwrap()
                .into_bigint()
                .0,
        ));
        let mut values = vec![
            BigUint::from(0u8),
            BigUint::from(1u8),
            &q - 1u8,
            q.clone(),
            &q + 1u8,
            &twice_q - 2u8,
            &twice_q - 1u8,
        ];
        for bit in [64usize, 128, 192, 253, 254] {
            let power = BigUint::from(1u8) << bit;
            values.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        for a in &values {
            for b in &values {
                check(a, b, &q, &r_inverse);
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6671_325f_6c61_7a79);
        for _ in 0..4096 {
            let a = integer(&U256::new(rng.random())) % &twice_q;
            let b = integer(&U256::new(rng.random())) % &twice_q;
            check(&a, &b, &q, &r_inverse);
            check(&a, &(&b % &q), &q, &r_inverse);
        }
    }
}
