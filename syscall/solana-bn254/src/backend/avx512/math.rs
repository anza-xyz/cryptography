//! High-throughput Montgomery CIOS IFMA Arithmetic.

#![allow(unused_unsafe)]
#![allow(unsafe_op_in_unsafe_fn)]

use super::types::FieldElement8x52;
use core::arch::x86_64::*;

// Mathematically pre-computed 52-bit modulus constants for the BN254 Fr field.
const FR_MOD_L0: i64 = 0x1f593f0000001;
const FR_MOD_L1: i64 = 0x4879b9709143e;
const FR_MOD_L2: i64 = 0x181585d2833e8;
const FR_MOD_L3: i64 = 0xa029b85045b68;
const FR_MOD_L4: i64 = 0x30644e72e131;

// The Montgomery Inverse Multiplier for 52-bit limbs: `(-MODULUS^-1) mod 2^52`
const FR_INV_52: i64 = 0x1f593efffffff;

/// Unreduced Parallel Addition.
///
/// Because IFMA math logically isolates results within a 52-bit boundary inside a
/// 64-bit accumulator lane, we naturally gain 12 bits of headroom. This function
/// can be called ~4,096 times consecutively before an overflow is mathematically
/// possible, making it extremely efficient for massive MDS matrix multiplications.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn add_lazy(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    FieldElement8x52 {
        l0: _mm512_add_epi64(a.l0, b.l0),
        l1: _mm512_add_epi64(a.l1, b.l1),
        l2: _mm512_add_epi64(a.l2, b.l2),
        l3: _mm512_add_epi64(a.l3, b.l3),
        l4: _mm512_add_epi64(a.l4, b.l4),
    }
}

/// Multiplies each lane by `2^4`, renormalizing to 52-bit limbs.
///
/// Used to reconcile Montgomery radices: five 52-bit CIOS iterations divide by
/// `2^260`, while the rest of the crate represents field elements with `R = 2^256`.
///
/// The input must be below `2^256`, which keeps the scaled result inside the
/// 260-bit window spanned by five limbs, so no significant bits are discarded.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn scale_by_16(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);

    let s0 = _mm512_slli_epi64(x.l0, 4);
    let s1 = _mm512_slli_epi64(x.l1, 4);
    let s2 = _mm512_slli_epi64(x.l2, 4);
    let s3 = _mm512_slli_epi64(x.l3, 4);
    let s4 = _mm512_slli_epi64(x.l4, 4);

    let mut out = FieldElement8x52::zero();

    let carry0 = _mm512_srli_epi64(s0, 52);
    out.l0 = _mm512_and_si512(s0, mask_52);

    let s1 = _mm512_add_epi64(s1, carry0);
    let carry1 = _mm512_srli_epi64(s1, 52);
    out.l1 = _mm512_and_si512(s1, mask_52);

    let s2 = _mm512_add_epi64(s2, carry1);
    let carry2 = _mm512_srli_epi64(s2, 52);
    out.l2 = _mm512_and_si512(s2, mask_52);

    let s3 = _mm512_add_epi64(s3, carry2);
    let carry3 = _mm512_srli_epi64(s3, 52);
    out.l3 = _mm512_and_si512(s3, mask_52);

    let s4 = _mm512_add_epi64(s4, carry3);
    out.l4 = _mm512_and_si512(s4, mask_52);

    out
}

/// Subtracts the modulus from every lane whose value is at least the modulus.
///
/// Yields a fully reduced result provided the input is below `2r`. This is what
/// lets a packed result be handed back to the scalar backend, whose `add` and
/// `sub` assume both operands are already below the modulus.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn cond_sub_modulus(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let mod0 = _mm512_set1_epi64(FR_MOD_L0);
    let mod1 = _mm512_set1_epi64(FR_MOD_L1);
    let mod2 = _mm512_set1_epi64(FR_MOD_L2);
    let mod3 = _mm512_set1_epi64(FR_MOD_L3);
    let mod4 = _mm512_set1_epi64(FR_MOD_L4);

    // Compute `x - MODULUS`, rippling the borrow across the 52-bit limbs. Each
    // limb difference lands in `(-2^52, 2^52)`, so its sign bit is exactly the
    // borrow out of that limb.
    let d0 = _mm512_sub_epi64(x.l0, mod0);
    let borrow0 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d0), -1);

    let d1 = _mm512_add_epi64(_mm512_sub_epi64(x.l1, mod1), borrow0);
    let borrow1 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d1), -1);

    let d2 = _mm512_add_epi64(_mm512_sub_epi64(x.l2, mod2), borrow1);
    let borrow2 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d2), -1);

    let d3 = _mm512_add_epi64(_mm512_sub_epi64(x.l3, mod3), borrow2);
    let borrow3 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d3), -1);

    let d4 = _mm512_add_epi64(_mm512_sub_epi64(x.l4, mod4), borrow3);

    // A borrow out of the top limb means `x < MODULUS`; keep the original lane.
    let underflow = _mm512_movepi64_mask(d4);

    FieldElement8x52 {
        l0: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d0, mask_52), x.l0),
        l1: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d1, mask_52), x.l1),
        l2: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d2, mask_52), x.l2),
        l3: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d3, mask_52), x.l3),
        l4: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d4, mask_52), x.l4),
    }
}

/// Computes an 8-way parallel Montgomery Multiplication for the BN254 Fr field.
///
/// Implements a fully unrolled CIOS (Coarsely Integrated Operand Scanning) algorithm.
/// Because IFMA tracks sums in a 64-bit accumulator, cross-product carries are
/// strictly contained within the active iteration and do not require ripple logic
/// between intermediate multiplies.
///
/// # Montgomery domain
/// Five 52-bit CIOS iterations divide by `2^260`, but field elements throughout
/// this crate are represented with `R = 2^256`. Pre-scaling `a` by `2^4` moves the
/// product back into the `2^256` domain. The correction is applied to the input
/// rather than the result because the CIOS reduction absorbs the extra magnitude
/// for free: correcting the output instead would require reducing a value as
/// large as `32r`.
///
/// # Contract
/// Both operands must be fully reduced (`< MODULUS`) Montgomery-form values, as
/// required by `MontgomeryBackend`. The result is fully reduced.
///
/// The operands are not symmetric in cost: `a` is scaled, `b` is not.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn mul_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    // 64-bit accumulators holding the in-flight summation.
    let mut t = [_mm512_setzero_si512(); 6];

    // Broadcast the 52-bit field constants into the AVX-512 lanes.
    let inv_vec = _mm512_set1_epi64(FR_INV_52);
    let mod0 = _mm512_set1_epi64(FR_MOD_L0);
    let mod1 = _mm512_set1_epi64(FR_MOD_L1);
    let mod2 = _mm512_set1_epi64(FR_MOD_L2);
    let mod3 = _mm512_set1_epi64(FR_MOD_L3);
    let mod4 = _mm512_set1_epi64(FR_MOD_L4);

    // Radix correction, see the note above.
    let a_scaled = scale_by_16(a);
    let a_limbs = [
        a_scaled.l0,
        a_scaled.l1,
        a_scaled.l2,
        a_scaled.l3,
        a_scaled.l4,
    ];

    // CIOS Algorithm: Loop is fully unrolled by the LLVM compiler.
    for i in 0..5 {
        let ai = a_limbs[i];

        // 1. Accumulate the multiplication of `ai` against all limbs of `b`.
        // `_mm512_madd52lo` adds the lower 52 bits of the product into the accumulator.
        // `_mm512_madd52hi` adds the upper 52 bits of the product into the accumulator.
        t[0] = _mm512_madd52lo_epu64(t[0], ai, b.l0);
        t[1] = _mm512_madd52hi_epu64(t[1], ai, b.l0);

        t[1] = _mm512_madd52lo_epu64(t[1], ai, b.l1);
        t[2] = _mm512_madd52hi_epu64(t[2], ai, b.l1);

        t[2] = _mm512_madd52lo_epu64(t[2], ai, b.l2);
        t[3] = _mm512_madd52hi_epu64(t[3], ai, b.l2);

        t[3] = _mm512_madd52lo_epu64(t[3], ai, b.l3);
        t[4] = _mm512_madd52hi_epu64(t[4], ai, b.l3);

        t[4] = _mm512_madd52lo_epu64(t[4], ai, b.l4);
        t[5] = _mm512_madd52hi_epu64(t[5], ai, b.l4);

        // 2. Compute Montgomery Multiplier: `m = (t[0] * INV) mod 2^52`
        // `madd52lo` automatically masks the inputs to 52 bits and ignores the high bits.
        let m = _mm512_madd52lo_epu64(_mm512_setzero_si512(), t[0], inv_vec);

        // 3. Accumulate Reduction: `t += m * Modulus`
        // Mathematically forces the bottom 52 bits of t[0] to exactly 0.
        t[0] = _mm512_madd52lo_epu64(t[0], m, mod0);
        t[1] = _mm512_madd52hi_epu64(t[1], m, mod0);

        t[1] = _mm512_madd52lo_epu64(t[1], m, mod1);
        t[2] = _mm512_madd52hi_epu64(t[2], m, mod1);

        t[2] = _mm512_madd52lo_epu64(t[2], m, mod2);
        t[3] = _mm512_madd52hi_epu64(t[3], m, mod2);

        t[3] = _mm512_madd52lo_epu64(t[3], m, mod3);
        t[4] = _mm512_madd52hi_epu64(t[4], m, mod3);

        t[4] = _mm512_madd52lo_epu64(t[4], m, mod4);
        t[5] = _mm512_madd52hi_epu64(t[5], m, mod4);

        // 4. Register shift down. Since the bottom 52 bits of t[0] are zero, we extract
        // the top carry and add it into the next limb, then rotate the array.
        let carry = _mm512_srli_epi64(t[0], 52);
        t[1] = _mm512_add_epi64(t[1], carry);

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = t[5];
        t[5] = _mm512_setzero_si512();
    }

    // --- 5. Final Carry Propagation ---
    // At the end of the CIOS loop, we strictly enforce the 52-bit boundaries
    // by propagating any overflowing bits from the 64-bit accumulators upwards.
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let mut out = FieldElement8x52::zero();

    let carry0 = _mm512_srli_epi64(t[0], 52);
    out.l0 = _mm512_and_si512(t[0], mask_52);

    let t1_new = _mm512_add_epi64(t[1], carry0);
    let carry1 = _mm512_srli_epi64(t1_new, 52);
    out.l1 = _mm512_and_si512(t1_new, mask_52);

    let t2_new = _mm512_add_epi64(t[2], carry1);
    let carry2 = _mm512_srli_epi64(t2_new, 52);
    out.l2 = _mm512_and_si512(t2_new, mask_52);

    let t3_new = _mm512_add_epi64(t[3], carry2);
    let carry3 = _mm512_srli_epi64(t3_new, 52);
    out.l3 = _mm512_and_si512(t3_new, mask_52);

    let t4_new = _mm512_add_epi64(t[4], carry3);
    out.l4 = _mm512_and_si512(t4_new, mask_52);

    // --- 6. Final Reduction ---
    // CIOS leaves the result below `2r`, not below `r`. The scalar backend's
    // `add` performs a single conditional subtraction and therefore requires
    // both operands to be fully reduced, so normalize before returning.
    cond_sub_modulus(&out)
}

/// Executes the Poseidon S-box (`x^5`) on 8 independent field elements simultaneously.
///
/// Because IFMA CIOS handles multiplication entirely in registers without branching
/// or memory spilling, this collapses what would normally be 24 scalar multiplications
/// into just 3 massive parallel SIMD dispatches.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn sbox_8x(x: &FieldElement8x52) -> FieldElement8x52 {
    let x2 = mul_8x(x, x);
    let x4 = mul_8x(&x2, &x2);
    mul_8x(&x4, x)
}
