//! Quadratic extension `Fq12 = Fq6[w]/(w^2-v)`.
//!
//! This is the entire extension field, including zero. It does not establish
//! membership in the pairing target group or the cyclotomic subgroup.
//! Fq coefficients remain canonical Montgomery residues with radix `2^256`.

use super::{Fq2, Fq6, frobenius};
use core::ops::{Add, Mul, Neg, Sub};

/// A field element `c0 + c1*w`, where `w^2 = v`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fq12 {
    pub(crate) c0: Fq6,
    pub(crate) c1: Fq6,
}

impl Fq12 {
    pub const ZERO: Self = Self::new(Fq6::ZERO, Fq6::ZERO);
    pub const ONE: Self = Self::new(Fq6::ONE, Fq6::ZERO);

    /// Constructs an element from already validated Fq6 coefficients.
    pub const fn new(c0: Fq6, c1: Fq6) -> Self {
        Self { c0, c1 }
    }

    /// Returns coefficients in the basis `[1, w]` over Fq6.
    pub const fn to_coefficients(&self) -> [Fq6; 2] {
        [self.c0, self.c1]
    }

    /// Squares an arbitrary Fq12 element using two Fq6 multiplications.
    #[inline]
    pub fn square(&self) -> Self {
        let ab = self.c0 * self.c1;
        Self::new(
            (self.c0 + self.c1) * (self.c0 + self.c1.mul_by_v()) - ab - ab.mul_by_v(),
            ab + ab,
        )
    }

    /// Returns the inverse, or `None` for zero.
    #[inline]
    pub fn inverse(&self) -> Option<Self> {
        let inverse = (self.c0.square() - self.c1.square().mul_by_v()).inverse()?;
        Some(Self::new(self.c0 * inverse, -(self.c1 * inverse)))
    }

    /// The `q^6`-power map: `c0+c1*w -> c0-c1*w`.
    /// This equals inversion only for elements whose relative norm is one.
    #[inline]
    pub fn conjugate(&self) -> Self {
        Self::new(self.c0, -self.c1)
    }

    /// Raises this element to `q^power`, where `q` is the Fq modulus.
    #[inline]
    pub fn frobenius(&self, power: usize) -> Self {
        let power = power % 12;
        if power == 0 {
            return *self;
        }
        Self::new(
            self.c0.frobenius(power),
            self.c1
                .frobenius(power)
                .mul_by_fq2(&frobenius::FQ12_C1[power]),
        )
    }

    /// Multiplies by the sparse line value `b0 + b3*w + b4*v*w`.
    /// The indices refer to the Fq2 basis `[1, v, v^2, w, v*w, v^2*w]`.
    #[inline]
    pub(crate) fn mul_by_034(&self, b0: &Fq2, b3: &Fq2, b4: &Fq2) -> Self {
        let a = self.c0.mul_by_fq2(b0);
        let b = self.c1.mul_by_01(b3, b4);
        Self::new(
            a + b.mul_by_v(),
            (self.c0 + self.c1).mul_by_01(&(*b0 + *b3), b4) - a - b,
        )
    }

    /// Six-product multiplication of two 034 line values.
    /// Same coefficient formulas as gnark-crypto v0.12.1 `Mul034By034`:
    /// <https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go>.
    #[inline]
    pub(crate) fn product_034(a: &[Fq2; 3], b: &[Fq2; 3]) -> [Fq2; 5] {
        let x0 = a[0] * b[0];
        let x3 = a[1] * b[1];
        let x4 = a[2] * b[2];
        let x04 = (a[0] + a[2]) * (b[0] + b[2]) - x0 - x4;
        let x03 = (a[0] + a[1]) * (b[0] + b[1]) - x0 - x3;
        let x34 = (a[1] + a[2]) * (b[1] + b[2]) - x3 - x4;
        [x0 + super::fq6::mul_by_xi(x4), x3, x34, x03, x04]
    }

    /// Applies a product of two lines in 17 Fq2 multiplications.
    /// See `MulBy01234` in the same gnark-crypto reference as `product_034`.
    #[inline]
    pub(crate) fn mul_by_01234(&self, b: &[Fq2; 5]) -> Self {
        let c0 = Fq6::new(b[0], b[1], b[2]);
        let c1 = Fq6::new(b[3], b[4], Fq2::ZERO);
        let a = self.c0 * c0;
        let d = self.c1.mul_by_01(&b[3], &b[4]);
        Self::new(a + d.mul_by_v(), (self.c0 + self.c1) * (c0 + c1) - a - d)
    }
}

impl Add for Fq12 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1)
    }
}

impl Sub for Fq12 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1)
    }
}

impl Neg for Fq12 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self::new(-self.c0, -self.c1)
    }
}

impl Mul for Fq12 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let a = self.c0 * rhs.c0;
        let b = self.c1 * rhs.c1;
        Self::new(
            a + b.mul_by_v(),
            (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - a - b,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::oracle::*;
    use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12};
    use ark_ff::{AdditiveGroup, Field as _};
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn sparse_multiplication_matches_dense_arkworks() {
        let mut rng = StdRng::seed_from_u64(0x746f_7765_725f_7370);
        // Every raw Montgomery coefficient is q-1, including the limb boundary.
        let raw_boundary = -ArkFq::ONE * ArkFq::from(2).pow([256]).inverse().unwrap();
        let c = ArkFq2::new(raw_boundary, raw_boundary);
        let c = ArkFq6::new(c, c, c);
        let boundary = ArkFq12::new(c, c);
        for i in 0..1024 {
            let a = if i == 0 { boundary } else { random12(&mut rng) };
            let b = if i == 0 { boundary } else { random12(&mut rng) };
            let [b0, b3, b4] = [b.c0.c0, b.c1.c0, b.c1.c1];
            for [b0, b3, b4] in [
                [ArkFq2::ZERO; 3],
                [b0, ArkFq2::ZERO, ArkFq2::ZERO],
                [ArkFq2::ZERO, b3, ArkFq2::ZERO],
                [ArkFq2::ZERO, ArkFq2::ZERO, b4],
                [b0, b3, b4],
            ] {
                let factor = ArkFq12::new(
                    ArkFq6::new(b0, ArkFq2::ZERO, ArkFq2::ZERO),
                    ArkFq6::new(b3, b4, ArkFq2::ZERO),
                );
                check12(
                    ours12(a).mul_by_034(&ours2(b0), &ours2(b3), &ours2(b4)),
                    a * factor,
                );
                check6(
                    ours6(a.c0).mul_by_01(&ours2(b0), &ours2(b3)),
                    a.c0 * ArkFq6::new(b0, b3, ArkFq2::ZERO),
                );
                check6(
                    ours6(a.c0).mul_by_fq2(&ours2(b0)),
                    a.c0 * ArkFq6::new(b0, ArkFq2::ZERO, ArkFq2::ZERO),
                );
            }
            let v = ArkFq6::new(ArkFq2::ZERO, ArkFq2::ONE, ArkFq2::ZERO);
            check6(ours6(a.c0).mul_by_v(), a.c0 * v);
        }
    }
}
