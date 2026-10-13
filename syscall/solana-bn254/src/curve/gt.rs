//! BN254 pairing target-group arithmetic for public data.
//!
//! Elements belong to the order-`r` multiplicative subgroup of Fq12, where
//! `r` is the scalar-field modulus. Coefficients retain the field tower's
//! canonical Montgomery representation with radix `2^256`.
//! Execution is variable-time, as permitted by the crate's public-data contract.

use crate::backend::{Fq12, U256};
use core::ops::Mul;

/// A nonzero Fq12 element whose `r`-th power is one.
///
/// Private storage preserves subgroup membership. The identity, including
/// `Default`, is field one; field zero is not a target-group element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(Fq12);

impl Gt {
    pub const IDENTITY: Self = Self(Fq12::ONE);

    /// Accepts only the sealed output of the verified final-exponentiation path.
    pub(crate) fn from_final_exponentiation(
        value: crate::pairing::final_exp::FinalExponentiation,
    ) -> Self {
        Self(value.into_fq12())
    }

    /// Validates membership in the order-`r` subgroup, accepting field one.
    ///
    /// Rejects zero and all nonmembers. Cyclotomic membership is verified
    /// before using subgroup-only formulas to check the order-r relation.
    pub fn from_fq12(value: Fq12) -> Option<Self> {
        crate::pairing::final_exp::is_in_target_group(value).then_some(Self(value))
    }

    /// Returns the underlying field element with canonical Montgomery coefficients.
    #[inline]
    pub const fn to_fq12(&self) -> Fq12 {
        self.0
    }

    #[inline]
    pub fn is_identity(&self) -> bool {
        *self == Self::IDENTITY
    }

    #[inline]
    pub fn square(&self) -> Self {
        Self(crate::pairing::final_exp::square_gt(self))
    }

    /// Returns the multiplicative inverse, which exists for every target-group element.
    #[inline]
    pub fn inverse(&self) -> Self {
        // r divides q^4-q^2+1, which divides q^6+1. Thus g^(q^6+1)=1
        // for every Gt element, and its q^6-power conjugate is its inverse.
        Self(self.0.conjugate())
    }

    /// Raises this element to an ordinary unsigned integer, accepting all 256 bits.
    ///
    /// The exponent is not a Montgomery Fr element and need not be below `r`.
    /// A zero exponent returns identity.
    pub fn pow(&self, exponent: &U256) -> Self {
        let Some(top) = exponent.0.iter().rposition(|&word| word != 0) else {
            return Self::IDENTITY;
        };
        let bits = top * 64 + 64 - exponent.0[top].leading_zeros() as usize;
        // The odd-power table costs three multiplications and one square.
        // Require at least four saved multiplications before constructing it.
        // Short or sparse exponents retain a binary schedule.
        let mut remaining = bits;
        let mut saved = 0;
        while remaining != 0 && saved < 4 {
            let high = remaining - 1;
            if exponent.0[high / 64] >> (high % 64) & 1 == 0 {
                remaining -= 1;
            } else {
                let (low, digit) = window3(exponent, high);
                saved += digit.count_ones() - 1;
                remaining = low;
            }
        }
        if saved < 4 {
            let mut result = *self;
            for bit in (0..bits - 1).rev() {
                result = result.square();
                if exponent.0[bit / 64] >> (bit % 64) & 1 != 0 {
                    result = result * *self;
                }
            }
            return result;
        }
        // Joint Frobenius powers amortize their preparation only for large exponents.
        if bits > 192
            && let Some(result) = pow_frobenius(self, exponent, bits)
        {
            return result;
        }
        pow_window3(self, exponent, bits)
    }
}

impl Default for Gt {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Mul for Gt {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

/// Reads an odd window of at most three bits, starting at a set high bit.
#[inline]
fn window3(exponent: &U256, high: usize) -> (usize, usize) {
    let mut low = high.saturating_sub(2);
    while exponent.0[low / 64] >> (low % 64) & 1 == 0 {
        low += 1;
    }
    let mut digit = 0;
    for bit in (low..=high).rev() {
        digit = (digit << 1) | ((exponent.0[bit / 64] >> (bit % 64)) & 1) as usize;
    }
    (low, digit)
}

// Sliding-window exponentiation (k=3), Handbook of Applied Cryptography,
// Algorithm 14.85: https://cacr.uwaterloo.ca/hac/about/chap14.pdf
// `pow` chooses the binary fallback using this implementation's table cost.
fn pow_window3(value: &Gt, exponent: &U256, bits: usize) -> Gt {
    let square = value.square();
    let mut odd = [*value; 4];
    for i in 1..odd.len() {
        odd[i] = odd[i - 1] * square;
    }
    let (mut remaining, first) = window3(exponent, bits - 1);
    let mut result = odd[first >> 1];
    while remaining != 0 {
        let high = remaining - 1;
        if exponent.0[high / 64] >> (high % 64) & 1 == 0 {
            result = result.square();
            remaining -= 1;
        } else {
            let (low, digit) = window3(exponent, high);
            for _ in low..remaining {
                result = result.square();
            }
            result = result * odd[digit >> 1];
            remaining = low;
        }
    }
    result
}

// q-r = 6*x^2. On validated Gt, g^q = g^(6*x^2), so exact division
// e = low + LAMBDA*high allows a joint exponent using g and Frobenius(g).
const GT_LAMBDA: u128 = 147946756881789318990833708069417712966;

// Exact unsigned division: the remainder is < 2^127 and the quotient < 2^130.
fn split_frobenius(exponent: &U256) -> (U256, U256) {
    let high = u128::from(exponent.0[2]) | (u128::from(exponent.0[3]) << 64);
    let low = u128::from(exponent.0[0]) | (u128::from(exponent.0[1]) << 64);
    let quotient_high = high / GT_LAMBDA;
    let mut remainder = high % GT_LAMBDA;
    let mut quotient_low = 0u128;
    for bit in (0..128).rev() {
        // remainder < lambda, so 2*remainder+bit < 2*lambda < 2^128.
        remainder = (remainder << 1) | ((low >> bit) & 1);
        if remainder >= GT_LAMBDA {
            remainder -= GT_LAMBDA;
            quotient_low |= 1u128 << bit;
        }
    }
    (
        U256::new([remainder as u64, (remainder >> 64) as u64, 0, 0]),
        U256::new([
            quotient_low as u64,
            (quotient_low >> 64) as u64,
            quotient_high as u64,
            0,
        ]),
    )
}

fn pow_frobenius(value: &Gt, exponent: &U256, bits: usize) -> Option<Gt> {
    let (mut remaining, _) = window3(exponent, bits - 1);
    let unsigned_squares = remaining + 1;
    let mut unsigned_muls = 3;
    while remaining != 0 {
        let high = remaining - 1;
        if exponent.0[high / 64] >> (high % 64) & 1 == 0 {
            remaining -= 1;
        } else {
            remaining = window3(exponent, high).0;
            unsigned_muls += 1;
        }
    }
    let unsigned_cost = unsigned_squares + 3 * unsigned_muls;
    let (low, high) = split_frobenius(exponent);
    let digits = [
        super::window::from_u256::<3>(&low),
        super::window::from_u256::<3>(&high),
    ];
    let len = digits[0].len.max(digits[1].len);
    let nonzero: usize = digits
        .iter()
        .map(|d| d.digits[..d.len].iter().filter(|&&x| x != 0).count())
        .sum();
    // Include both odd-power tables and a conservative margin for Frobenius,
    // division, recoding and signed selection. This affects speed, not results.
    let joint_cost = len + 1 + 3 * (nonzero + 1) + 10;
    if joint_cost >= unsigned_cost {
        return None;
    }
    let image = Gt(value.0.frobenius(1));
    let odd = [
        *value,
        value.square() * *value,
        image,
        image.square() * image,
    ];
    let table = [
        [odd[0], odd[1], odd[0].inverse(), odd[1].inverse()],
        [odd[2], odd[3], odd[2].inverse(), odd[3].inverse()],
    ];
    let mut result: Option<Gt> = None;
    for bit in (0..len).rev() {
        if let Some(acc) = result {
            result = Some(acc.square());
        }
        for j in 0..2 {
            let digit = digits[j].digits[bit];
            if digit != 0 {
                let index = (digit.unsigned_abs() >> 1) as usize + if digit < 0 { 2 } else { 0 };
                let term = table[j][index];
                result = Some(match result {
                    Some(acc) => acc * term,
                    None => term,
                });
            }
        }
    }
    result
}

#[cfg(test)]
mod frobenius_tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn integer(value: U256) -> BigUint {
        value
            .0
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |v, &w| (v << 64) + w)
    }
    fn limbs(value: &BigUint) -> U256 {
        let digits = value.to_u64_digits();
        let mut result = [0; 4];
        result[..digits.len()].copy_from_slice(&digits);
        U256::new(result)
    }
    #[test]
    fn exact_frobenius_split_matches_big_integer_division() {
        let q = BigUint::from_bytes_le(&ark_bn254::Fq::MODULUS.to_bytes_le());
        let r = BigUint::from_bytes_le(&ark_bn254::Fr::MODULUS.to_bytes_le());
        let lambda = BigUint::from(GT_LAMBDA);
        assert_eq!(q - r, lambda);
        assert_eq!(GT_LAMBDA, 6 * u128::from(crate::curve::g2::BN_X).pow(2));
        let limit = BigUint::from(1u8) << 256usize;
        let mut cases = std::vec![BigUint::from(0u8), &limit - 1u8];
        for bit in 0..256usize {
            let center = BigUint::from(1u8) << bit;
            cases.extend([&center - 1u8, center.clone(), &center + 1u8]);
        }
        let mut rng = StdRng::seed_from_u64(0x6774_5f66_726f_6231);
        for _ in 0..4096 {
            let n = integer(U256::new(rng.random()));
            let center = (&n / &lambda) * &lambda;
            cases.push(n);
            if center != BigUint::from(0u8) {
                cases.push(&center - 1u8);
            }
            cases.extend([center.clone(), &center + 1u8]);
        }
        for n in cases {
            if n >= limit {
                continue;
            }
            let (lo, hi) = split_frobenius(&limbs(&n));
            let lo = integer(lo);
            let hi = integer(hi);
            assert!(lo.bits() <= 127 && hi.bits() <= 130);
            assert_eq!((&lo, &hi), (&(&n % &lambda), &(&n / &lambda)));
            assert_eq!(lo + lambda.clone() * hi, n);
        }
    }
}
