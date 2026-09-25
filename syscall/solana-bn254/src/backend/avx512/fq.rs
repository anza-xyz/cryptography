//! Fq IFMA arithmetic for independent products inside extension-field operations.
//!
//! Adapted from the crate's Fr CIOS kernel with independently derived Fq
//! constants. Inputs and outputs use R=2^256. Private product inputs are <2q; scaling
//! one operand by 16 makes five CIOS steps return ab/2^256. Since 4q<R,
//! a,b<2q imply 16ab<q*2^260 and the reduced quotient is below 2q. Within each of five
//! CIOS iterations each lane accumulates only a bounded number of 52-bit
//! products, below 2^58, leaving ample space in its u64 accumulator.
//!
//! CIOS reference: Koc, Acar and Kaliski, Section 5,
//! <https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf>.
//! IFMA instruction semantics:
//! <https://doc.rust-lang.org/core/arch/x86_64/fn._mm512_madd52lo_epu64.html>.
//! The packed Fq2 formula products and radix correction are local adaptations.

#![allow(unused_unsafe)]
#![allow(unsafe_op_in_unsafe_fn)]

use super::types::FieldElement8x52;
use core::arch::x86_64::*;

// Mathematically pre-computed 52-bit modulus constants for the BN254 Fq field.
const FQ_MOD_L0: i64 = 0x8c16d87cfd47;
const FQ_MOD_L1: i64 = 0x916871ca8d3c2;
const FQ_MOD_L2: i64 = 0x181585d97816a;
const FQ_MOD_L3: i64 = 0xa029b85045b68;
const FQ_MOD_L4: i64 = 0x30644e72e131;

// The Montgomery Inverse Multiplier for 52-bit limbs: `(-MODULUS^-1) mod 2^52`
const FQ_INV_52: i64 = 0x20782e4866389;

#[cfg(test)]
/// Adds two normalized vectors before immediate carry normalization.
/// Each limb sum is below 2^53, safely inside its 64-bit accumulator lane.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn add_lazy(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    FieldElement8x52 {
        l0: _mm512_add_epi64(a.l0, b.l0),
        l1: _mm512_add_epi64(a.l1, b.l1),
        l2: _mm512_add_epi64(a.l2, b.l2),
        l3: _mm512_add_epi64(a.l3, b.l3),
        l4: _mm512_add_epi64(a.l4, b.l4),
    }
}

#[cfg(test)]
/// Adds canonical Fq operands and returns normalized limbs representing <2q.
///
/// Both operands must have normalized 52-bit limbs and represent values below
/// q. Their sum is below 2q < 2^255. Each limb sum, including a carry of at
/// most one, is below 2^53, so 64-bit lanes cannot overflow. Normalize the
/// carries before using the sum as a private multiplication input.
///
/// Addition preserves the external R = 2^256 Montgomery representation.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn add_unreduced(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let sum = add_lazy(a, b);
    let s1 = _mm512_add_epi64(sum.l1, _mm512_srli_epi64(sum.l0, 52));
    let s2 = _mm512_add_epi64(sum.l2, _mm512_srli_epi64(s1, 52));
    let s3 = _mm512_add_epi64(sum.l3, _mm512_srli_epi64(s2, 52));
    let s4 = _mm512_add_epi64(sum.l4, _mm512_srli_epi64(s3, 52));
    FieldElement8x52 {
        l0: _mm512_and_si512(sum.l0, mask_52),
        l1: _mm512_and_si512(s1, mask_52),
        l2: _mm512_and_si512(s2, mask_52),
        l3: _mm512_and_si512(s3, mask_52),
        // The complete sum is below 2^255, so this limb is below 2^47.
        l4: s4,
    }
}

#[cfg(test)]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn add_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    cond_sub_modulus(&add_unreduced(a, b))
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
/// Yields a fully reduced result provided the input is below `2q`. This is what
/// lets a packed result be handed back to the scalar backend, whose `add` and
/// `sub` assume both operands are already below the modulus.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn cond_sub_modulus(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let mod0 = _mm512_set1_epi64(FQ_MOD_L0);
    let mod1 = _mm512_set1_epi64(FQ_MOD_L1);
    let mod2 = _mm512_set1_epi64(FQ_MOD_L2);
    let mod3 = _mm512_set1_epi64(FQ_MOD_L3);
    let mod4 = _mm512_set1_epi64(FQ_MOD_L4);

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

/// Computes an 8-way parallel Montgomery Multiplication for the BN254 Fq field.
///
/// Implements five CIOS (Coarsely Integrated Operand Scanning) iterations.
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
/// large as `32q`.
///
/// # Contract
/// Both private operands may be below 2q, with normalized 52-bit limbs. Since
/// 4q<R, their product is below qR and the radix-corrected reduction needs only
/// one subtraction. This does not relax the public MontgomeryBackend contract.
///
/// The operands are not symmetric in cost: `a` is scaled, `b` is not.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
#[allow(clippy::needless_range_loop)] // Keep the audited CIOS limb schedule explicit.
unsafe fn mul_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    // 64-bit accumulators holding the in-flight summation.
    let mut t = [_mm512_setzero_si512(); 6];

    // Broadcast the 52-bit field constants into the AVX-512 lanes.
    let inv_vec = _mm512_set1_epi64(FQ_INV_52);
    let mod0 = _mm512_set1_epi64(FQ_MOD_L0);
    let mod1 = _mm512_set1_epi64(FQ_MOD_L1);
    let mod2 = _mm512_set1_epi64(FQ_MOD_L2);
    let mod3 = _mm512_set1_epi64(FQ_MOD_L3);
    let mod4 = _mm512_set1_epi64(FQ_MOD_L4);

    // Radix correction, see the note above.
    let a_scaled = scale_by_16(a);
    let a_limbs = [
        a_scaled.l0,
        a_scaled.l1,
        a_scaled.l2,
        a_scaled.l3,
        a_scaled.l4,
    ];

    // Five 52-bit CIOS steps.
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
    // CIOS leaves the result below `2q`, not below `r`. The scalar backend's
    // `add` performs a single conditional subtraction and therefore requires
    // both operands to be fully reduced, so normalize before returning.
    cond_sub_modulus(&out)
}

#[cfg(test)]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn sub_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    let a = [a.l0, a.l1, a.l2, a.l3, a.l4];
    let b = [b.l0, b.l1, b.l2, b.l3, b.l4];
    let p = [FQ_MOD_L0, FQ_MOD_L1, FQ_MOD_L2, FQ_MOD_L3, FQ_MOD_L4];
    let mask = _mm512_set1_epi64(0xfffffffffffff);
    let mut d = [_mm512_setzero_si512(); 5];
    let mut borrow = _mm512_setzero_si512();
    for i in 0..5 {
        d[i] = _mm512_add_epi64(_mm512_sub_epi64(a[i], b[i]), borrow);
        borrow = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d[i]), -1);
    }
    let underflow = _mm512_movepi64_mask(d[4]);
    let mut carry = _mm512_setzero_si512();
    for i in 0..5 {
        let value = _mm512_add_epi64(
            _mm512_add_epi64(
                _mm512_and_si512(d[i], mask),
                _mm512_maskz_set1_epi64(underflow, p[i]),
            ),
            carry,
        );
        d[i] = _mm512_and_si512(value, mask);
        carry = _mm512_srli_epi64(value, 52);
    }
    // Discard the carry beyond 260 bits after correcting a negative difference.
    FieldElement8x52 {
        l0: d[0],
        l1: d[1],
        l2: d[2],
        l3: d[3],
        l4: d[4],
    }
}

// Private integer sum for immediate input to the packed multiplier. Canonical
// a,b<q imply a+b<2q<2^255, so the four-limb addition cannot overflow. pack_8x
// normalizes the radix-52 limbs, and mul_8x's existing <2q contract applies.
// This value must never be returned as a canonical Fq2 coefficient.
#[inline]
fn sum_g2_coefficients(a: &crate::backend::U256, b: &crate::backend::U256) -> crate::backend::U256 {
    use crate::backend::{Backend, Fq, MontgomeryBackend, U256};
    type B = Backend<Fq>;
    debug_assert!(B::is_reduced(a) && B::is_reduced(b));
    let mut words = [0; 4];
    let mut carry = 0u128;
    for (i, word) in words.iter_mut().enumerate() {
        let value = a.0[i] as u128 + b.0[i] as u128 + carry;
        *word = value as u64;
        carry = value >> 64;
    }
    debug_assert_eq!(carry, 0);
    U256::new(words)
}

/// Two Fq2 squares and one independent Fq2 product, using seven of eight lanes.
/// Input/output coefficients are canonical R=2^256 Montgomery Fq residues.
///
/// # Safety
/// Requires AVX-512 F, DQ and IFMA on the executing CPU.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(crate) unsafe fn fq2_two_squares_and_product(
    squares: [crate::backend::Fq2; 2],
    a: crate::backend::Fq2,
    b: crate::backend::Fq2,
) -> [crate::backend::Fq2; 3] {
    use super::pack::{pack_8x, unpack_8x};
    use crate::backend::{Backend, Fq, Fq2, MontgomeryBackend, U256};
    type B = Backend<Fq>;
    let [x, y] = squares;
    let lhs = [
        sum_g2_coefficients(&x.c0, &x.c1),
        x.c0,
        sum_g2_coefficients(&y.c0, &y.c1),
        y.c0,
        a.c0,
        a.c1,
        sum_g2_coefficients(&a.c0, &a.c1),
        U256::zero(),
    ];
    let rhs = [
        B::sub(&x.c0, &x.c1),
        x.c1,
        B::sub(&y.c0, &y.c1),
        y.c1,
        b.c0,
        b.c1,
        sum_g2_coefficients(&b.c0, &b.c1),
        U256::zero(),
    ];
    let p = unpack_8x(&mul_8x(&pack_8x(&lhs), &pack_8x(&rhs)));
    [
        Fq2 {
            c0: p[0],
            c1: B::add(&p[1], &p[1]),
        },
        Fq2 {
            c0: p[2],
            c1: B::add(&p[3], &p[3]),
        },
        Fq2 {
            c0: B::sub(&p[4], &p[5]),
            c1: B::sub(&B::sub(&p[6], &p[4]), &p[5]),
        },
    ]
}

/// Three independent Fq2 squares, using six of eight lanes.
/// Input/output coefficients are canonical R=2^256 Montgomery Fq residues.
///
/// # Safety
/// Requires AVX-512 F, DQ and IFMA on the executing CPU.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(crate) unsafe fn fq2_three_squares(
    values: [crate::backend::Fq2; 3],
) -> [crate::backend::Fq2; 3] {
    use super::pack::{pack_8x, unpack_8x};
    use crate::backend::{Backend, Fq, Fq2, MontgomeryBackend, U256};
    type B = Backend<Fq>;
    let lhs = core::array::from_fn(|i| {
        if i >= 6 {
            return U256::zero();
        }
        let x = values[i / 2];
        if i % 2 == 0 {
            sum_g2_coefficients(&x.c0, &x.c1)
        } else {
            x.c0
        }
    });
    let rhs = core::array::from_fn(|i| {
        if i >= 6 {
            return U256::zero();
        }
        let x = values[i / 2];
        if i % 2 == 0 {
            B::sub(&x.c0, &x.c1)
        } else {
            x.c1
        }
    });
    let p = unpack_8x(&mul_8x(&pack_8x(&lhs), &pack_8x(&rhs)));
    core::array::from_fn(|i| Fq2 {
        c0: p[2 * i],
        c1: B::add(&p[2 * i + 1], &p[2 * i + 1]),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn packed_g2_formula_products_match_arkworks() {
        let inv = ArkFq2::new(
            ArkFq::from(2u64).pow([256u64]).inverse().unwrap(),
            ArkFq::ZERO,
        );
        let check = |values: [Fq2; 4]| {
            let ark = |x: Fq2| ArkFq2::new(field(x.c0), field(x.c1));
            let raw_pair = |x: ArkFq2| Fq2 {
                c0: raw(x.c0),
                c1: raw(x.c1),
            };
            let mixed = unsafe {
                fq2_two_squares_and_product([values[0], values[1]], values[2], values[3])
            };
            assert_eq!(
                mixed,
                [
                    raw_pair(ark(values[0]).square() * inv),
                    raw_pair(ark(values[1]).square() * inv),
                    raw_pair(ark(values[2]) * ark(values[3]) * inv),
                ]
            );
            let squares = unsafe { fq2_three_squares([values[0], values[1], values[2]]) };
            for i in 0..3 {
                assert_eq!(squares[i], raw_pair(ark(values[i]).square() * inv));
            }
        };
        let one = ArkFq::ONE;
        let mut values = vec![raw(ArkFq::ZERO), raw(one), raw(-one), raw(-one - one)];
        for bit in [
            1, 51, 52, 53, 103, 104, 105, 155, 156, 157, 207, 208, 209, 252, 253,
        ] {
            let power = ArkFq::from(2u64).pow([bit]);
            values.extend([raw(power - one), raw(power), raw(power + one)]);
        }
        for i in 0..values.len() {
            for j in 0..values.len() {
                check(core::array::from_fn(|k| Fq2 {
                    c0: values[(i + k) % values.len()],
                    c1: values[(j + 3 * k) % values.len()],
                }));
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6732_5f69_666d_616b);
        for _ in 0..1024 {
            check(core::array::from_fn(|_| Fq2 {
                c0: random(&mut rng),
                c1: random(&mut rng),
            }));
        }
    }

    extern crate std;
    use super::super::pack::{pack_8x, unpack_8x};
    use super::*;
    use crate::backend::{Fq2, U256};
    use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2};
    use ark_ff::{AdditiveGroup as _, BigInt, Field as _, PrimeField};
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::vec;

    fn field(v: U256) -> ArkFq {
        ArkFq::from_bigint(BigInt(v.0)).unwrap()
    }
    fn raw(v: ArkFq) -> U256 {
        U256::new(v.into_bigint().0)
    }
    fn random(rng: &mut StdRng) -> U256 {
        raw(ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()))
    }
    fn check(a: [U256; 8], b: [U256; 8], inv: ArkFq) {
        let (sum, difference, product) = unsafe {
            let x = pack_8x(&a);
            let y = pack_8x(&b);
            (
                unpack_8x(&add_8x(&x, &y)),
                unpack_8x(&sub_8x(&x, &y)),
                unpack_8x(&mul_8x(&x, &y)),
            )
        };
        for i in 0..8 {
            assert_eq!(sum[i], raw(field(a[i]) + field(b[i])));
            assert_eq!(difference[i], raw(field(a[i]) - field(b[i])));
            assert_eq!(product[i], raw(field(a[i]) * field(b[i]) * inv));
        }
    }
    #[test]
    fn packed_fq_boundaries_and_random_inputs_match_arkworks() {
        let inv = ArkFq::from(2).pow([256]).inverse().unwrap();
        let one = ArkFq::ONE;
        let mut values = vec![raw(ArkFq::ZERO), raw(one), raw(-one), raw(-one - one)];
        for bit in [
            1, 51, 52, 53, 103, 104, 105, 155, 156, 157, 207, 208, 209, 252, 253,
        ] {
            let power = ArkFq::from(2).pow([bit]);
            values.extend([raw(power - one), raw(power), raw(power + one)]);
        }
        for i in 0..values.len() {
            for j in 0..values.len() {
                check(
                    core::array::from_fn(|k| values[(i + k) % values.len()]),
                    core::array::from_fn(|k| values[(j + 3 * k) % values.len()]),
                    inv,
                );
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6966_6d61_5f66_7131);
        for _ in 0..512 {
            check(
                core::array::from_fn(|_| random(&mut rng)),
                core::array::from_fn(|_| random(&mut rng)),
                inv,
            );
        }
    }
    #[test]
    fn packed_private_lazy_products_match_big_integer_oracle() {
        use ark_ff::BigInteger;
        use num_bigint::BigUint;
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let bound = 2u8 * &q;
        let inv = BigUint::from_bytes_le(
            &ArkFq::from(2)
                .pow([256])
                .inverse()
                .unwrap()
                .into_bigint()
                .to_bytes_le(),
        );
        let raw = |n: &BigUint| {
            let mut a = [0; 4];
            let words = n.to_u64_digits();
            assert!(words.len() <= 4);
            a[..words.len()].copy_from_slice(&words);
            U256::new(a)
        };
        let integer = |n: U256| BigUint::from_bytes_le(&BigInt(n.0).to_bytes_le());
        let check = |a: [U256; 8], b: [U256; 8]| {
            let out = unsafe { unpack_8x(&mul_8x(&pack_8x(&a), &pack_8x(&b))) };
            for k in 0..8 {
                assert!(integer(a[k]) < bound && integer(b[k]) < bound);
                assert_eq!(integer(out[k]), integer(a[k]) * integer(b[k]) * &inv % &q);
            }
        };
        let values = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            &q - 1u8,
            q.clone(),
            &q + 1u8,
            &bound - 2u8,
            &bound - 1u8,
        ];
        for i in 0..values.len() {
            for j in 0..values.len() {
                check(
                    core::array::from_fn(|k| raw(&values[(i + k) % values.len()])),
                    core::array::from_fn(|k| raw(&values[(j + 3 * k) % values.len()])),
                );
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6966_6d61_6c61_7a79);
        for _ in 0..512 {
            check(
                core::array::from_fn(|_| raw(&(integer(U256::new(rng.random())) % &bound))),
                core::array::from_fn(|_| raw(&(integer(U256::new(rng.random())) % &bound))),
            );
        }
    }
}
