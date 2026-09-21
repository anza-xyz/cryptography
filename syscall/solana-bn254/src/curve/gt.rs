//! BN254 pairing target-group arithmetic for public data.
//!
//! Elements belong to the order-`r` multiplicative subgroup of Fq12, where
//! `r` is the scalar-field modulus. Coefficients retain the field tower's
//! canonical Montgomery representation with radix `2^256`.
//! Execution is variable-time, as permitted by the crate's public-data contract.

use crate::backend::{Field, Fq12, Fr, U256};
use core::ops::Mul;

/// A nonzero Fq12 element whose `r`-th power is one.
///
/// Private storage preserves subgroup membership. The identity, including
/// `Default`, is field one; field zero is not a target-group element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(Fq12);

impl Gt {
    pub const IDENTITY: Self = Self(Fq12::ONE);

    /// Validates membership in the order-`r` subgroup, accepting field one.
    ///
    /// Rejects zero and all nonmembers. This uses generic field exponentiation:
    /// reducing the exponent modulo `r` or using subgroup-only formulas here
    /// would assume the property being checked.
    pub fn from_fq12(value: Fq12) -> Option<Self> {
        (value != Fq12::ZERO && pow_field(&value, &Fr::MODULUS) == Fq12::ONE).then_some(Self(value))
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
        Self(self.0.square())
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
            let mut result = self.0;
            for bit in (0..bits - 1).rev() {
                result = result.square();
                if exponent.0[bit / 64] >> (bit % 64) & 1 != 0 {
                    result = result * self.0;
                }
            }
            return Self(result);
        }
        Self(pow_window3(&self.0, exponent, bits))
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

/// Binary exponentiation on the entire field, with an ordinary integer exponent.
/// In particular, the subgroup check must evaluate the full exponent r.
fn pow_field(value: &Fq12, exponent: &U256) -> Fq12 {
    let mut result = Fq12::ONE;
    let mut started = false;
    for limb in exponent.0.iter().rev() {
        for bit in (0..64).rev() {
            if started {
                result = result.square();
            }
            if limb >> bit & 1 != 0 {
                result = if started { result * *value } else { *value };
                started = true;
            }
        }
    }
    result
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
fn pow_window3(value: &Fq12, exponent: &U256, bits: usize) -> Fq12 {
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
