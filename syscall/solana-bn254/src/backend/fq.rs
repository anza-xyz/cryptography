//! BN254 Base Field (Fq) configuration and static addition chains.

use super::{Backend, Field, MontgomeryBackend, U256};

/// BN254 Base Field parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Fq;

impl Field for Fq {
    const MODULUS: U256 = U256::new([
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);
    const INV: u64 = 0x87d20782e4866389;
    const R2: U256 = U256::new([
        0xf32cfc5b538afa89,
        0xb5e71911d44501fb,
        0x47ab1eff0a417ff6,
        0x06d89f71cab8351f,
    ]);
}

impl Fq {
    /// Computes `a^(p-2) mod p` using a static 4-bit window addition chain.
    #[inline(always)]
    pub fn invert(a: &U256) -> U256 {
        type B = Backend<Fq>;
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
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a7);
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
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..4 {
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
        t = B::mul(&t, &a6);
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
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a13);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a2);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a13);
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
        t = B::mul(&t, &a12);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a13);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        t
    }

    /// Computes `a^((p+1)/4) mod p` using a static 4-bit window addition chain.
    #[inline(always)]
    pub fn sqrt(a: &U256) -> U256 {
        type B = Backend<Fq>;
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

        let mut t = a12;
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
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
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a9);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
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
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
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
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a13);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a7);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a6);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a14);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a5);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a10);
        for _ in 0..4 {
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
        t = B::mul(&t, &a10);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a12);
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
        t = B::mul(&t, &a10);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a4);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..8 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a8);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a2);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
        for _ in 0..8 {
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
        t = B::mul(&t, a);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a15);
        for _ in 0..4 {
            t = B::sqr(&t);
        }
        t = B::mul(&t, &a3);
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
        t = B::mul(&t, &a2);
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fq_invert() {
        type B = Backend<Fq>;
        let val = B::to_mont(&U256::new([5, 0, 0, 0]));
        let inv = Fq::invert(&val);
        let check = B::mul(&val, &inv);
        assert_eq!(B::from_mont(&check), U256::one());

        // Zero inversion maps to zero in prime fields via Fermat's Little Thm
        let zero = U256::zero();
        assert_eq!(Fq::invert(&zero), U256::zero());
    }

    #[test]
    fn test_fq_sqrt() {
        type B = Backend<Fq>;
        // sqrt(25) = 5
        let sqr = B::to_mont(&U256::new([25, 0, 0, 0]));
        let root = Fq::sqrt(&sqr);

        // Ensure our root squares exactly back to the original value
        let check = B::sqr(&root);
        assert_eq!(B::from_mont(&check), U256::new([25, 0, 0, 0]));
    }
}
