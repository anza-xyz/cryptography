//! Cubic extension `Fq6 = Fq2[v]/(v^3 - (9+u))`, where `u^2 = -1`.
//!
//! All Fq coefficients remain canonical Montgomery residues with radix `2^256`.
//! Private scalar/SIMD Fq2 helpers and the nonresidue multiplier reduce their
//! bounded intermediate accumulators before returning canonical coefficients.

use super::{Fq2, frobenius};
use core::ops::{Add, Mul, Neg, Sub};

/// A field element `c0 + c1*v + c2*v^2` with canonical Fq2 coefficients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fq6 {
    pub(crate) c0: Fq2,
    pub(crate) c1: Fq2,
    pub(crate) c2: Fq2,
}

mod nonresidue;
pub(crate) use nonresidue::mul_by_xi;

impl Fq6 {
    pub const ZERO: Self = Self::new(Fq2::ZERO, Fq2::ZERO, Fq2::ZERO);
    pub const ONE: Self = Self::new(Fq2::ONE, Fq2::ZERO, Fq2::ZERO);

    /// Constructs an element from already validated Fq2 coefficients.
    pub const fn new(c0: Fq2, c1: Fq2, c2: Fq2) -> Self {
        Self { c0, c1, c2 }
    }

    /// Returns coefficients in the basis `[1, v, v^2]`.
    pub const fn to_coefficients(&self) -> [Fq2; 3] {
        [self.c0, self.c1, self.c2]
    }

    /// Squares using three Fq2 squares and two Fq2 multiplications.
    #[inline]
    pub fn square(&self) -> Self {
        let s0 = self.c0.square();
        let a0a1 = self.c0 * self.c1;
        let s1 = a0a1 + a0a1;
        let s2 = (self.c0 - self.c1 + self.c2).square();
        let a1a2 = self.c1 * self.c2;
        let s3 = a1a2 + a1a2;
        let s4 = self.c2.square();
        // s1+s2+s3-s0-s4 = a1^2 + 2*a0*a2.
        Self::new(
            s0 + mul_by_xi(s3),
            s1 + mul_by_xi(s4),
            s1 + s2 + s3 - s0 - s4,
        )
    }

    /// Returns the inverse, or `None` for zero.
    #[inline]
    pub fn inverse(&self) -> Option<Self> {
        // Multiplication by t0+t1*v+t2*v^2 eliminates both nonconstant terms.
        let t0 = self.c0.square() - mul_by_xi(self.c1 * self.c2);
        let t1 = mul_by_xi(self.c2.square()) - self.c0 * self.c1;
        let t2 = self.c1.square() - self.c0 * self.c2;
        let norm = self.c0 * t0 + mul_by_xi(self.c2 * t1 + self.c1 * t2);
        let inverse = norm.inverse()?;
        Some(Self::new(t0 * inverse, t1 * inverse, t2 * inverse))
    }

    /// Multiplies by `v`, using `v^3 = 9+u`.
    #[inline]
    pub fn mul_by_v(&self) -> Self {
        Self::new(mul_by_xi(self.c2), self.c0, self.c1)
    }

    /// Multiplies all coefficients by an Fq2 element.
    #[inline]
    pub fn mul_by_fq2(&self, rhs: &Fq2) -> Self {
        Self::new(self.c0 * *rhs, self.c1 * *rhs, self.c2 * *rhs)
    }

    /// Multiplies by `b0 + b1*v` using five Fq2 multiplications.
    #[inline]
    pub fn mul_by_01(&self, b0: &Fq2, b1: &Fq2) -> Self {
        let a0b0 = self.c0 * *b0;
        let a1b1 = self.c1 * *b1;
        Self::new(
            a0b0 + mul_by_xi(self.c2 * *b1),
            (self.c0 + self.c1) * (*b0 + *b1) - a0b0 - a1b1,
            self.c2 * *b0 + a1b1,
        )
    }

    /// Raises this element to `q^power`, where `q` is the Fq modulus.
    #[inline]
    pub fn frobenius(&self, power: usize) -> Self {
        let power = power % 6;
        if power == 0 {
            return *self;
        }
        let mut result = *self;
        if power % 2 == 1 {
            result.c0 = result.c0.conjugate();
            result.c1 = result.c1.conjugate();
            result.c2 = result.c2.conjugate();
        }
        result.c1 = result.c1 * frobenius::FQ6_C1[power];
        result.c2 = result.c2 * frobenius::FQ6_C2[power];
        result
    }
}

impl Add for Fq6 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1, self.c2 + rhs.c2)
    }
}

impl Sub for Fq6 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1, self.c2 - rhs.c2)
    }
}

impl Neg for Fq6 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self::new(-self.c0, -self.c1, -self.c2)
    }
}

impl Mul for Fq6 {
    type Output = Self;
    // Six-product Karatsuba in the cubic tower; see Aranha et al., Section 3:
    // https://eprint.iacr.org/2010/526
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(all(
            target_arch = "x86_64",
            target_feature = "avx512f",
            target_feature = "avx512dq",
            target_feature = "avx512ifma"
        ))]
        {
            // SAFETY: compile-time gating requires all vector features. Every
            // input coefficient is a canonical Fq2 value; private inner sums
            // remain below 2q and the vector helper returns canonical values.
            let [a0b0, a1b1, a2b2, cross12, cross01, cross02] = unsafe {
                super::avx512::fq::mul_fq2_6(
                    [
                        self.c0,
                        self.c1,
                        self.c2,
                        self.c1 + self.c2,
                        self.c0 + self.c1,
                        self.c0 + self.c2,
                    ],
                    [
                        rhs.c0,
                        rhs.c1,
                        rhs.c2,
                        rhs.c1 + rhs.c2,
                        rhs.c0 + rhs.c1,
                        rhs.c0 + rhs.c2,
                    ],
                )
            };
            Self::new(
                a0b0 + mul_by_xi(cross12 - a1b1 - a2b2),
                cross01 - a0b0 - a1b1 + mul_by_xi(a2b2),
                cross02 - a0b0 - a2b2 + a1b1,
            )
        }
        #[cfg(not(all(
            target_arch = "x86_64",
            target_feature = "avx512f",
            target_feature = "avx512dq",
            target_feature = "avx512ifma"
        )))]
        {
            let a0b0 = self.c0 * rhs.c0;
            let a1b1 = self.c1 * rhs.c1;
            let a2b2 = self.c2 * rhs.c2;
            // Six-product Karatsuba multiplication, reduced using v^3 = xi.
            Self::new(
                a0b0 + mul_by_xi((self.c1 + self.c2) * (rhs.c1 + rhs.c2) - a1b1 - a2b2),
                (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - a0b0 - a1b1 + mul_by_xi(a2b2),
                (self.c0 + self.c2) * (rhs.c0 + rhs.c2) - a0b0 - a2b2 + a1b1,
            )
        }
    }
}
