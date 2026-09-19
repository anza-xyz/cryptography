//! BN254 quadratic extension Fq[u]/(u^2+1).
//!
//! Each coefficient is a canonical Montgomery Fq residue with radix `2^256`.
//! Products may use private input sums below `2q`; every returned coefficient
//! is canonical, with the same Montgomery radix.

use super::{Backend, Fq, MontgomeryBackend, U256, portable::FqSum};
use core::ops::{Add, Mul, Neg, Sub};

type B = Backend<Fq>;

/// A quadratic extension element `c0 + c1*u`, where `u^2 = -1`.
/// Private coefficients preserve canonical Montgomery representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fq2 {
    pub(crate) c0: U256,
    pub(crate) c1: U256,
}

impl Fq2 {
    pub const ZERO: Self = Self {
        c0: U256::zero(),
        c1: U256::zero(),
    };
    pub const ONE: Self = Self {
        c0: U256::new([
            0xd35d438dc58f0d9d,
            0x0a78eb28f5c70b3d,
            0x666ea36f7879462c,
            0x0e0a77c19a07df2f,
        ]),
        c1: U256::zero(),
    };

    /// Accepts two reduced Montgomery Fq coefficients.
    pub fn from_montgomery(c0: U256, c1: U256) -> Option<Self> {
        (B::is_reduced(&c0) && B::is_reduced(&c1)).then_some(Self { c0, c1 })
    }

    /// Returns `(c0, c1)` as canonical Montgomery Fq residues.
    #[inline]
    pub fn to_montgomery(&self) -> (U256, U256) {
        (self.c0, self.c1)
    }

    /// Computes the square with two base-field multiplications.
    #[inline]
    pub fn square(&self) -> Self {
        let product = B::mul(&self.c0, &self.c1);
        Self {
            c0: FqSum::new(&self.c0, &self.c1).product_reduced(&B::sub(&self.c0, &self.c1)),
            c1: B::add(&product, &product),
        }
    }

    /// Returns the inverse, or None for zero.
    #[inline]
    pub fn inverse(&self) -> Option<Self> {
        // q = 3 (mod 4), so -1 is a nonsquare in Fq. Thus c0^2+c1^2
        // vanishes exactly when both coefficients vanish.
        let norm = B::add(&B::sqr(&self.c0), &B::sqr(&self.c1));
        let inverse = B::inv(&norm)?;
        Some(Self {
            c0: B::mul(&self.c0, &inverse),
            c1: B::neg(&B::mul(&self.c1, &inverse)),
        })
    }

    /// The q-power Frobenius map: `(c0, c1) -> (c0, -c1)`.
    #[inline]
    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: B::neg(&self.c1),
        }
    }
}

impl Add for Fq2 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: B::add(&self.c0, &rhs.c0),
            c1: B::add(&self.c1, &rhs.c1),
        }
    }
}
impl Sub for Fq2 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: B::sub(&self.c0, &rhs.c0),
            c1: B::sub(&self.c1, &rhs.c1),
        }
    }
}
impl Neg for Fq2 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self {
            c0: B::neg(&self.c0),
            c1: B::neg(&self.c1),
        }
    }
}
impl Mul for Fq2 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let a = B::mul(&self.c0, &rhs.c0);
        let b = B::mul(&self.c1, &rhs.c1);
        let cross = FqSum::new(&self.c0, &self.c1).product(FqSum::new(&rhs.c0, &rhs.c1));
        Self {
            c0: B::sub(&a, &b),
            c1: B::sub(&B::sub(&cross, &a), &b),
        }
    }
}
