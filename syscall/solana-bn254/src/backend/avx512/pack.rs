//! Conversion bridge between public 4-limb arrays and internal 5-limb SIMD vectors.

#![allow(unused_unsafe)]
#![allow(unsafe_op_in_unsafe_fn)]

use super::types::FieldElement8x52;
use crate::backend::U256;
use core::arch::x86_64::{_mm512_loadu_si512, _mm512_set1_epi64, _mm512_storeu_si512};

/// Constant bitmask used to isolate exactly 52 bits during packing boundaries.
const MASK_52: u64 = 0xFFFFFFFFFFFFF;

/// Packs an array of 8 scalar 4-limb (64-bit) U256s into a single 5-limb (52-bit) AVX-512 vector.
///
/// This acts as the zero-cost API boundary, safely translating the public 64-bit
/// little-endian storage layouts into our internal 52-bit SIMD math engine.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn pack_8x(inputs: &[U256; 8]) -> FieldElement8x52 {
    let mut l0 = [0u64; 8];
    let mut l1 = [0u64; 8];
    let mut l2 = [0u64; 8];
    let mut l3 = [0u64; 8];
    let mut l4 = [0u64; 8];

    // Iteratively bit-slice the 4x64-bit boundaries into 5x52-bit boundaries.
    for i in 0..8 {
        let u = &inputs[i].0;
        l0[i] = u[0] & MASK_52;
        l1[i] = ((u[0] >> 52) | (u[1] << 12)) & MASK_52;
        l2[i] = ((u[1] >> 40) | (u[2] << 24)) & MASK_52;
        l3[i] = ((u[2] >> 28) | (u[3] << 36)) & MASK_52;
        l4[i] = u[3] >> 16;
    }

    FieldElement8x52 {
        l0: _mm512_loadu_si512(l0.as_ptr() as *const _),
        l1: _mm512_loadu_si512(l1.as_ptr() as *const _),
        l2: _mm512_loadu_si512(l2.as_ptr() as *const _),
        l3: _mm512_loadu_si512(l3.as_ptr() as *const _),
        l4: _mm512_loadu_si512(l4.as_ptr() as *const _),
    }
}

/// Unpacks a 5-limb AVX-512 vector into a mutable array of 8 scalar U256s.
///
/// Reconstructs the original base `2^{64}` boundaries by masking and shifting
/// the processed 52-bit SIMD lanes.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn unpack_8x_into(packed: &FieldElement8x52, outputs: &mut [U256; 8]) {
    let mut l0 = [0u64; 8];
    let mut l1 = [0u64; 8];
    let mut l2 = [0u64; 8];
    let mut l3 = [0u64; 8];
    let mut l4 = [0u64; 8];

    _mm512_storeu_si512(l0.as_mut_ptr() as *mut _, packed.l0);
    _mm512_storeu_si512(l1.as_mut_ptr() as *mut _, packed.l1);
    _mm512_storeu_si512(l2.as_mut_ptr() as *mut _, packed.l2);
    _mm512_storeu_si512(l3.as_mut_ptr() as *mut _, packed.l3);
    _mm512_storeu_si512(l4.as_mut_ptr() as *mut _, packed.l4);

    // Reconstruct 64-bit boundaries by reversing the shifts.
    for i in 0..8 {
        let u0 = l0[i] | (l1[i] << 52);
        let u1 = (l1[i] >> 12) | (l2[i] << 40);
        let u2 = (l2[i] >> 24) | (l3[i] << 28);
        let u3 = (l3[i] >> 36) | (l4[i] << 16);
        outputs[i] = U256::new([u0, u1, u2, u3]);
    }
}

/// Allocates and unpacks a 5-limb AVX-512 vector into an array of 8 scalar U256s.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn unpack_8x(packed: &FieldElement8x52) -> [U256; 8] {
    let mut out = [U256::zero(); 8];
    unpack_8x_into(packed, &mut out);
    out
}

/// Broadcasts a single scalar 4-limb value identically to all 8 lanes of a SIMD register.
///
/// Important for Poseidon matrix multiplication, where a single state element must
/// be multiplied against an entire SIMD chunk of the matrix column vector.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn broadcast(u: &U256) -> FieldElement8x52 {
    let l0 = u.0[0] & MASK_52;
    let l1 = ((u.0[0] >> 52) | (u.0[1] << 12)) & MASK_52;
    let l2 = ((u.0[1] >> 40) | (u.0[2] << 24)) & MASK_52;
    let l3 = ((u.0[2] >> 28) | (u.0[3] << 36)) & MASK_52;
    let l4 = u.0[3] >> 16;

    FieldElement8x52 {
        l0: _mm512_set1_epi64(l0 as i64),
        l1: _mm512_set1_epi64(l1 as i64),
        l2: _mm512_set1_epi64(l2 as i64),
        l3: _mm512_set1_epi64(l3 as i64),
        l4: _mm512_set1_epi64(l4 as i64),
    }
}
