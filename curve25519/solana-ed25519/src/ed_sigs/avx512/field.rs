//! Field arithmetic for the AVX-512 verifier.
//!
//! `Fe51` wraps the crate's `FieldElement`. The IFMA lanes need every limb
//! `< 2^52`; the crate reduces in every operation except `AddAssign`, which is
//! lazy by design, so `add` here reduces eagerly.

use crate::backend::serial::u64::constants::{EDWARDS_D, EDWARDS_D2, SQRT_M1};
use crate::field::FieldElement;
use subtle::ConstantTimeEq;

// Number of 51-bit limbs needed to represent a value modulo p = 2^255 - 19.
pub(crate) const LIMB_COUNT: usize = 5;

const LOOSE_LIMB_BOUND: u64 = 1 << 52;

pub(crate) const D_LIMBS: [u64; LIMB_COUNT] = EDWARDS_D.0;
pub(crate) const TWO_D_LIMBS: [u64; LIMB_COUNT] = EDWARDS_D2.0;
pub(crate) const SQRT_M1_LIMBS: [u64; LIMB_COUNT] = SQRT_M1.0;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe51(FieldElement);

impl Fe51 {
    /// Weakly reduce arbitrary limbs; every observer canonicalizes anyway.
    pub(crate) fn from_limbs(limbs: [u64; LIMB_COUNT]) -> Self {
        Self(FieldElement::reduce(limbs))
    }

    /// Store limbs without canonicalizing. Valid only when each limb is already
    /// `< 2^52` (the loosely-reduced invariant), e.g. straight from a wide reduce.
    pub(crate) fn from_limbs_unchecked(limbs: [u64; LIMB_COUNT]) -> Self {
        debug_assert!(limbs.iter().all(|&limb| limb < LOOSE_LIMB_BOUND));
        Self(FieldElement::from_limbs(limbs))
    }

    pub(crate) fn zero() -> Self {
        Self(FieldElement::ZERO)
    }

    pub(crate) fn one() -> Self {
        Self(FieldElement::ONE)
    }

    pub(crate) fn d() -> Self {
        Self(EDWARDS_D)
    }

    pub(crate) fn two_d() -> Self {
        Self(EDWARDS_D2)
    }

    // "Unchecked" means canonicality only; limb masking still yields `< 2^51`
    // limbs, safe for every field op here.
    pub(crate) fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self(FieldElement::from_bytes(bytes))
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn add(&self, rhs: &Self) -> Self {
        Self(FieldElement::reduce((&self.0 + &rhs.0).0))
    }

    pub(crate) fn subtract(&self, rhs: &Self) -> Self {
        Self(&self.0 - &rhs.0)
    }

    pub(crate) fn negate(&self) -> Self {
        Self(-&self.0)
    }

    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }

    pub(crate) fn multiply(&self, rhs: &Self) -> Self {
        Self(&self.0 * &rhs.0)
    }

    pub(crate) fn square(&self) -> Self {
        Self(self.0.square())
    }

    // The root's sign is arbitrary; `EdwardsPoint::decompress` fixes it from
    // the encoding's sign bit.
    pub(crate) fn sqrt_ratio(u: &Self, v: &Self) -> Option<Self> {
        let (is_square, root) = FieldElement::sqrt_ratio_i(&u.0, &v.0);
        bool::from(is_square).then_some(Self(root))
    }

    pub(crate) fn is_odd(&self) -> bool {
        bool::from(self.0.is_negative())
    }

    pub(crate) fn equals(&self, rhs: &Self) -> bool {
        bool::from(self.0.ct_eq(&rhs.0))
    }

    /// Loosely reduced limbs for AVX-512 IFMA field arithmetic.
    pub(crate) fn loose_limbs(&self) -> [u64; LIMB_COUNT] {
        debug_assert!(self.0.0.iter().all(|&limb| limb < LOOSE_LIMB_BOUND));
        self.0.0
    }

    // Exposed to tests to cross-check the SIMD exponentiation chain.
    #[cfg(test)]
    pub(crate) fn pow_p_minus_5_over_8(&self) -> Self {
        Self(self.0.pow_p58())
    }

    #[cfg(test)]
    pub(crate) fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `Fe51` that reaches the IFMA lanes must have limbs `< 2^52`.
    /// `add` is the one operation the crate does not reduce for us, so drive
    /// the operations that feed the bridge and check the bound holds.
    #[test]
    fn every_operation_keeps_limbs_below_the_loose_bound() {
        let mut state = 0x2545f4914f6cdd1du64;
        let mut next = || {
            state = state
                .wrapping_mul(0xd1342543de82ef95)
                .wrapping_add(0x9e3779b97f4a7c15);
            state
        };
        let check = |x: &Fe51, what: &str| {
            assert!(
                x.0.0.iter().all(|&limb| limb < LOOSE_LIMB_BOUND),
                "{what} left a limb >= 2^52: {:?}",
                x.0.0
            );
        };

        let mut round = 0;
        while round < 512 {
            let a = Fe51::from_limbs(core::array::from_fn(|_| next()));
            let b = Fe51::from_limbs(core::array::from_fn(|_| next()));
            check(&a, "from_limbs");

            check(&a.add(&b), "add");
            check(&a.subtract(&b), "subtract");
            check(&a.multiply(&b), "multiply");
            check(&a.square(), "square");
            check(&a.negate(), "negate");
            check(&a.double(), "double");
            check(&a.pow_p_minus_5_over_8(), "pow_p_minus_5_over_8");
            check(&a.invert(), "invert");
            check(&Fe51::from_bytes_unchecked(&a.to_bytes()), "from_bytes");
            if let Some(root) = Fe51::sqrt_ratio(&a, &b) {
                check(&root, "sqrt_ratio");
            }

            // Repeated adds are where a lazy `Add` would silently blow the
            // bound, so chain enough of them to catch it.
            let mut acc = a;
            for _ in 0..64 {
                acc = acc.add(&b);
            }
            check(&acc, "chained add");
            round += 1;
        }

        check(&Fe51::zero(), "zero");
        check(&Fe51::one(), "one");
        check(&Fe51::d(), "d");
        check(&Fe51::two_d(), "two_d");
        for (limbs, what) in [
            (D_LIMBS, "D_LIMBS"),
            (TWO_D_LIMBS, "TWO_D_LIMBS"),
            (SQRT_M1_LIMBS, "SQRT_M1_LIMBS"),
        ] {
            assert!(
                limbs.iter().all(|&limb| limb < LOOSE_LIMB_BOUND),
                "{what} has a limb >= 2^52"
            );
        }
    }

    #[test]
    fn square_matches_multiply_self() {
        let cases = [
            [0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0],
            [
                1_234_567_890_123,
                2_222_222_222_222,
                987_654_321_987,
                1_111_111_111_111,
                333_333_333_333,
            ],
        ];

        for limbs in cases {
            let x = Fe51::from_limbs(limbs);
            assert!(x.square().equals(&x.multiply(&x)));
        }
    }
}
