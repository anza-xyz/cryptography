//! Fundamental data layout for AVX-512 batched cryptography.

use core::arch::x86_64::__m512i;

/// Holds 8 independent 256-bit field elements in parallel, packed into 52-bit limbs.
///
/// A standard 256-bit scalar is mathematically represented as:
/// `X = l0 + (l1 << 52) + (l2 << 104) + (l3 << 156) + (l4 << 208)`
///
/// We use a **Struct of Arrays (SoA)** layout (Vertical Vectorization).
/// Instead of one SIMD register holding the limbs of a single field element,
/// each `__m512i` register holds the *same* limb slice across 8 distinct elements.
/// This perfectly isolates carries within vertical lanes, allowing 100% horizontal
/// lane utilization.
#[derive(Copy, Clone)]
pub struct FieldElement8x52 {
    /// Limb 0 (Bits 0-51) for elements 0 through 7.
    pub l0: __m512i,
    /// Limb 1 (Bits 52-103) for elements 0 through 7.
    pub l1: __m512i,
    /// Limb 2 (Bits 104-155) for elements 0 through 7.
    pub l2: __m512i,
    /// Limb 3 (Bits 156-207) for elements 0 through 7.
    pub l3: __m512i,
    /// Limb 4 (Bits 208-255) for elements 0 through 7. (Effectively 48-bits wide).
    pub l4: __m512i,
}

impl FieldElement8x52 {
    /// Returns an instance where all 8 field elements are strictly zero.
    #[inline(always)]
    pub fn zero() -> Self {
        unsafe {
            use core::arch::x86_64::_mm512_setzero_si512;
            Self {
                l0: _mm512_setzero_si512(),
                l1: _mm512_setzero_si512(),
                l2: _mm512_setzero_si512(),
                l3: _mm512_setzero_si512(),
                l4: _mm512_setzero_si512(),
            }
        }
    }
}
