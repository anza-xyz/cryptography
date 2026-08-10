//! BN254 Scalar Field (Fr) configuration and static addition chains.

use super::{Backend, Field, MontgomeryBackend, U256};

/// BN254 Scalar Field parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Fr;

impl Field for Fr {
    const MODULUS: U256 = U256::new([
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);
    const INV: u64 = 0xc2e1f593efffffff;
    const R2: U256 = U256::new([
        0x1bb8e645ae216da7,
        0x53fe3ab1e35c59e3,
        0x8c49833d53bb8085,
        0x0216d0b17f4e44a5,
    ]);
}

impl Fr {
    /// Computes the modular inverse of `a` in the scalar field Fr.
    ///
    /// Computes `a^(r-2) mod r` via Fermat's Little Theorem, where `r` is
    /// the Fr modulus.
    ///
    /// Like the Fq implementation, this strictly avoids dynamic branching or
    /// loops in favor of a static 4-bit window addition chain.
    #[inline(always)]
    pub fn invert(a: &U256) -> U256 {
        type B = Backend<Fr>;
        let a2 = B::sqr(a);
        let a3 = B::mul(&a2, a);
        let a4 = B::sqr(&a2);
        let a5 = B::mul(&a4, a);
        let a6 = B::sqr(&a3);
        let a7 = B::mul(&a6, a);
        let a8 = B::sqr(&a4);
        let a9 = B::mul(&a8, a);
        let a10 = B::sqr(&a5);
        let a11 = B::mul(&a10, a);
        let a12 = B::sqr(&a6);
        let a13 = B::mul(&a12, a);
        let a14 = B::sqr(&a7);
        let a15 = B::mul(&a14, a);

        let mut t = a3;
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a7);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a2);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a2);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a11);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a11);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a13);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a2);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a7);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a11);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a7);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_invert() {
        type B = Backend<Fr>;
        let val = B::to_mont(&U256::new([5, 0, 0, 0]));
        let inv = Fr::invert(&val);
        let check = B::mul(&val, &inv);
        assert_eq!(B::from_mont(&check), U256::one());
    }
}
