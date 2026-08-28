//! Traits for field parameters and Montgomery arithmetic backends.

use super::u256::U256;

/// Compile-time configuration for a specific prime field (e.g., Fq or Fr).
pub trait Field: Send + Sync + 'static {
    /// The prime modulus of the field.
    const MODULUS: U256;

    /// The Montgomery inverse parameter: `-MODULUS^{-1} mod 2^64`.
    /// Critical for fast, division-free Montgomery reduction.
    const INV: u64;

    /// R^2 mod MODULUS. Used to move elements into Montgomery form.
    const R2: U256;
}

/// Generic trait defining a Montgomery arithmetic backend.
///
/// # Safety and Preconditions
/// ALL functions in this trait strictly assume that inputs are fully reduced
/// field elements (i.e., `x < F::MODULUS`). Passing unreduced `U256` integers
/// will result in silently incorrect math, as the internal trial subtractions
/// and overflow logic are optimized for a maximum intermediate value of
/// `2 * MODULUS - 2`.
///
/// Implementations process field elements in Montgomery form. Because
/// this crate operates on public data, constant-time execution is
/// explicitly NOT required. Implementations will rely on fast conditional
/// branches (e.g., simple subtraction for final reduction).
pub trait MontgomeryBackend<F: Field> {
    /// Computes `(a + b) mod MODULUS`.
    fn add(a: &U256, b: &U256) -> U256;

    /// Computes `(a - b) mod MODULUS`.
    fn sub(a: &U256, b: &U256) -> U256;

    /// Computes `(a * b * R^-1) mod MODULUS` using Montgomery reduction.
    fn mul(a: &U256, b: &U256) -> U256;

    /// Computes `(a * a * R^-1) mod MODULUS`.
    fn sqr(a: &U256) -> U256;

    /// Computes `(-a) mod MODULUS`.
    fn neg(a: &U256) -> U256;

    /// Converts a normal integer into Montgomery form: `mul(a, R^2)`.
    #[inline(always)]
    fn to_mont(a: &U256) -> U256 {
        Self::mul(a, &F::R2)
    }

    /// Converts a value out of Montgomery form: `mul(a, 1)`.
    #[inline(always)]
    fn from_mont(a: &U256) -> U256 {
        Self::mul(a, &U256::one())
    }

    /// Returns `true` when `a` is a fully reduced field element (`a < MODULUS`).
    ///
    /// All other operations in this trait assume reduced inputs; this is the
    /// check callers use at a trust boundary before relying on that.
    #[inline(always)]
    fn is_reduced(a: &U256) -> bool {
        let m = F::MODULUS.0;
        for i in (0..4).rev() {
            if a.0[i] != m[i] {
                return a.0[i] < m[i];
            }
        }
        false
    }
}
