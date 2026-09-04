// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.
//
// AVX-512 IFMA kernels for the lane-per-signature field layer.
//
// Bounds contract: `mul`, `square`, `sub` and `neg` return limbs below 2^52;
// `add` returns raw limb sums, below 2^53 for in-contract inputs. VPMADD52
// truncates its multiplicands to 52 bits, so `mul` and `square` carry-reduce
// their operands first and accept any limbs the portable path produces.

#![allow(non_snake_case)]
// Nightly and stable currently disagree on the requirement of unsafe blocks
// when intrinsics are called inside `#[target_feature]` functions.
#![allow(unused_unsafe)]

use core::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_and_epi64, _mm512_loadu_si512, _mm512_madd52hi_epu64,
    _mm512_madd52lo_epu64, _mm512_set1_epi64, _mm512_slli_epi64, _mm512_srli_epi64,
    _mm512_storeu_si512, _mm512_sub_epi64,
};

use super::field_x8::FieldElementX8;

// `avx512bw` is what the x8 SHA-512 gather byte-swaps with.
cpufeatures::new!(cpuid_avx512ifma_x8, "avx512f", "avx512bw", "avx512ifma");

/// Whether the running CPU supports the kernels in this module.
#[inline]
pub(crate) fn available() -> bool {
    cpuid_avx512ifma_x8::init().get()
}

// Small helpers, all compiled with the target feature so they inline into the
// kernels below.

macro_rules! tf {
    ($(#[$meta:meta])* fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty $body:block) => {
        $(#[$meta])*
        #[target_feature(enable = "avx512ifma")]
        #[inline]
        unsafe fn $name($($arg: $ty),*) -> $ret $body
    };
}

tf!(
    fn splat(v: u64) -> __m512i {
        unsafe { _mm512_set1_epi64(v as i64) }
    }
);

tf!(
    fn add(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_add_epi64(a, b) }
    }
);

tf!(
    fn sub(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_sub_epi64(a, b) }
    }
);

tf!(
    fn and(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_and_epi64(a, b) }
    }
);

tf!(
    fn madd52lo(z: __m512i, x: __m512i, y: __m512i) -> __m512i {
        unsafe { _mm512_madd52lo_epu64(z, x, y) }
    }
);

tf!(
    fn madd52hi(z: __m512i, x: __m512i, y: __m512i) -> __m512i {
        unsafe { _mm512_madd52hi_epu64(z, x, y) }
    }
);

macro_rules! shl {
    ($x:expr, $n:literal) => {
        _mm512_slli_epi64($x, $n)
    };
}

macro_rules! shr {
    ($x:expr, $n:literal) => {
        _mm512_srli_epi64($x, $n)
    };
}

tf!(
    fn load(fe: &FieldElementX8) -> [__m512i; 5] {
        unsafe {
            [
                _mm512_loadu_si512(fe.limbs[0].as_ptr() as *const _),
                _mm512_loadu_si512(fe.limbs[1].as_ptr() as *const _),
                _mm512_loadu_si512(fe.limbs[2].as_ptr() as *const _),
                _mm512_loadu_si512(fe.limbs[3].as_ptr() as *const _),
                _mm512_loadu_si512(fe.limbs[4].as_ptr() as *const _),
            ]
        }
    }
);

tf!(
    fn store(x: [__m512i; 5]) -> FieldElementX8 {
        let mut out = FieldElementX8::ZERO;
        unsafe {
            for (limbs, v) in out.limbs.iter_mut().zip(x.iter()) {
                _mm512_storeu_si512(limbs.as_mut_ptr() as *mut _, *v);
            }
        }
        out
    }
);

// One carry pass: masks each limb to 51 bits, propagates carries upward, and
// folds the top carry back with weight 19. Accepts arbitrary 64-bit limbs and
// returns limbs below 2^52.
tf!(
    fn carry_reduce(x: [__m512i; 5]) -> [__m512i; 5] {
        unsafe {
            let mask = splat((1 << 51) - 1);
            let r19 = splat(19);

            let c0 = shr!(x[0], 51);
            let c1 = shr!(x[1], 51);
            let c2 = shr!(x[2], 51);
            let c3 = shr!(x[3], 51);
            let c4 = shr!(x[4], 51);

            [
                madd52lo(and(x[0], mask), c4, r19),
                add(and(x[1], mask), c0),
                add(and(x[2], mask), c1),
                add(and(x[3], mask), c2),
                add(and(x[4], mask), c3),
            ]
        }
    }
);

// Kernels. Safety: the caller must have verified `available()`.

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn add_x8(a: &FieldElementX8, b: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = load(a);
        let y = load(b);
        store([
            add(x[0], y[0]),
            add(x[1], y[1]),
            add(x[2], y[2]),
            add(x[3], y[3]),
            add(x[4], y[4]),
        ])
    }
}

/// Sixteen times the prime, limb-wise: the bias that keeps subtractions nonnegative.
const P_TIMES_16_LO: u64 = 36028797018963664; // 16 * (2^51 - 19)
const P_TIMES_16_HI: u64 = 36028797018963952; // 16 * (2^51 - 1)

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn sub_x8(a: &FieldElementX8, b: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = load(a);
        let y = load(b);
        let lo = splat(P_TIMES_16_LO);
        let hi = splat(P_TIMES_16_HI);
        store(carry_reduce([
            sub(add(x[0], lo), y[0]),
            sub(add(x[1], hi), y[1]),
            sub(add(x[2], hi), y[2]),
            sub(add(x[3], hi), y[3]),
            sub(add(x[4], hi), y[4]),
        ]))
    }
}

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn neg_x8(a: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = load(a);
        let lo = splat(P_TIMES_16_LO);
        let hi = splat(P_TIMES_16_HI);
        store(carry_reduce([
            sub(lo, x[0]),
            sub(hi, x[1]),
            sub(hi, x[2]),
            sub(hi, x[3]),
            sub(hi, x[4]),
        ]))
    }
}

/// The F51x4 multiplication waves on eight lanes, emitted textually so several
/// products can be scheduled in one function. Limbs in and out are below 2^52.
macro_rules! mul_waves_raw_emit {
    ($xe:expr, $ye:expr) => {{
        let x: [__m512i; 5] = $xe;
        let y: [__m512i; 5] = $ye;

        unsafe {
            // Accumulators for terms with coeff 1
            let mut z0_1 = splat(0);
            let mut z1_1 = splat(0);
            let mut z2_1 = splat(0);
            let mut z3_1 = splat(0);
            let mut z4_1 = splat(0);
            let mut z5_1 = splat(0);
            let mut z6_1 = splat(0);
            let mut z7_1 = splat(0);
            let mut z8_1 = splat(0);

            // Accumulators for terms with coeff 2
            let mut z0_2 = splat(0);
            let mut z1_2 = splat(0);
            let mut z2_2 = splat(0);
            let mut z3_2 = splat(0);
            let mut z4_2 = splat(0);
            let mut z5_2 = splat(0);
            let mut z6_2 = splat(0);
            let mut z7_2 = splat(0);
            let mut z8_2 = splat(0);
            let mut z9_2 = splat(0);

            // Wave 0
            z4_1 = madd52lo(z4_1, x[2], y[2]);
            z5_2 = madd52hi(z5_2, x[2], y[2]);
            z5_1 = madd52lo(z5_1, x[4], y[1]);
            z6_2 = madd52hi(z6_2, x[4], y[1]);
            z6_1 = madd52lo(z6_1, x[4], y[2]);
            z7_2 = madd52hi(z7_2, x[4], y[2]);
            z7_1 = madd52lo(z7_1, x[4], y[3]);
            z8_2 = madd52hi(z8_2, x[4], y[3]);

            // Wave 1
            z4_1 = madd52lo(z4_1, x[3], y[1]);
            z5_2 = madd52hi(z5_2, x[3], y[1]);
            z5_1 = madd52lo(z5_1, x[3], y[2]);
            z6_2 = madd52hi(z6_2, x[3], y[2]);
            z6_1 = madd52lo(z6_1, x[3], y[3]);
            z7_2 = madd52hi(z7_2, x[3], y[3]);
            z7_1 = madd52lo(z7_1, x[3], y[4]);
            z8_2 = madd52hi(z8_2, x[3], y[4]);

            // Wave 2
            z8_1 = madd52lo(z8_1, x[4], y[4]);
            z9_2 = madd52hi(z9_2, x[4], y[4]);
            z4_1 = madd52lo(z4_1, x[4], y[0]);
            z5_2 = madd52hi(z5_2, x[4], y[0]);
            z5_1 = madd52lo(z5_1, x[2], y[3]);
            z6_2 = madd52hi(z6_2, x[2], y[3]);
            z6_1 = madd52lo(z6_1, x[2], y[4]);
            z7_2 = madd52hi(z7_2, x[2], y[4]);

            let z8 = add(z8_1, add(z8_2, z8_2));
            let z9 = add(z9_2, z9_2);

            // Wave 3
            z3_1 = madd52lo(z3_1, x[3], y[0]);
            z4_2 = madd52hi(z4_2, x[3], y[0]);
            z4_1 = madd52lo(z4_1, x[1], y[3]);
            z5_2 = madd52hi(z5_2, x[1], y[3]);
            z5_1 = madd52lo(z5_1, x[1], y[4]);
            z6_2 = madd52hi(z6_2, x[1], y[4]);
            z2_1 = madd52lo(z2_1, x[2], y[0]);
            z3_2 = madd52hi(z3_2, x[2], y[0]);

            let z6 = add(z6_1, add(z6_2, z6_2));
            let z7 = add(z7_1, add(z7_2, z7_2));

            // Wave 4
            z3_1 = madd52lo(z3_1, x[2], y[1]);
            z4_2 = madd52hi(z4_2, x[2], y[1]);
            z4_1 = madd52lo(z4_1, x[0], y[4]);
            z5_2 = madd52hi(z5_2, x[0], y[4]);
            z1_1 = madd52lo(z1_1, x[1], y[0]);
            z2_2 = madd52hi(z2_2, x[1], y[0]);
            z2_1 = madd52lo(z2_1, x[1], y[1]);
            z3_2 = madd52hi(z3_2, x[1], y[1]);

            let z5 = add(z5_1, add(z5_2, z5_2));

            // Wave 5
            z3_1 = madd52lo(z3_1, x[1], y[2]);
            z4_2 = madd52hi(z4_2, x[1], y[2]);
            z0_1 = madd52lo(z0_1, x[0], y[0]);
            z1_2 = madd52hi(z1_2, x[0], y[0]);
            z1_1 = madd52lo(z1_1, x[0], y[1]);
            z2_1 = madd52lo(z2_1, x[0], y[2]);
            z2_2 = madd52hi(z2_2, x[0], y[1]);
            z3_2 = madd52hi(z3_2, x[0], y[2]);

            let mut t0 = splat(0);
            let mut t1 = splat(0);
            let r19 = splat(19);

            // Wave 6
            t0 = madd52hi(t0, r19, z9);
            t1 = madd52lo(t1, r19, shr!(z9, 52));
            z3_1 = madd52lo(z3_1, x[0], y[3]);
            z4_2 = madd52hi(z4_2, x[0], y[3]);
            z1_2 = madd52lo(z1_2, r19, shr!(z5, 52));
            z2_2 = madd52lo(z2_2, r19, shr!(z6, 52));
            z3_2 = madd52lo(z3_2, r19, shr!(z7, 52));
            z0_1 = madd52lo(z0_1, r19, z5);

            // Wave 7
            z4_1 = madd52lo(z4_1, r19, z9);
            z1_1 = madd52lo(z1_1, r19, z6);
            z0_2 = madd52lo(z0_2, r19, add(t0, t1));
            z4_2 = madd52hi(z4_2, r19, z8);
            z2_1 = madd52lo(z2_1, r19, z7);
            z1_2 = madd52hi(z1_2, r19, z5);
            z2_2 = madd52hi(z2_2, r19, z6);
            z3_2 = madd52hi(z3_2, r19, z7);

            // Wave 8
            z3_1 = madd52lo(z3_1, r19, z8);
            z4_2 = madd52lo(z4_2, r19, shr!(z8, 52));

            [
                add(z0_1, add(z0_2, z0_2)),
                add(z1_1, add(z1_2, z1_2)),
                add(z2_1, add(z2_2, z2_2)),
                add(z3_1, add(z3_2, z3_2)),
                add(z4_1, add(z4_2, z4_2)),
            ]
        }
    }};
}

#[target_feature(enable = "avx512ifma")]
unsafe fn mul_waves(x: [__m512i; 5], y: [__m512i; 5]) -> [__m512i; 5] {
    unsafe { carry_reduce(mul_waves_raw_emit!(x, y)) }
}

/// The multiplication waves without the trailing carry pass: for operands below
/// 2^52 the result limbs are below 18 * 2^52 < 2^57.
#[target_feature(enable = "avx512ifma")]
unsafe fn mul_waves_raw(x: [__m512i; 5], y: [__m512i; 5]) -> [__m512i; 5] {
    mul_waves_raw_emit!(x, y)
}

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn mul_x8(a: &FieldElementX8, b: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = carry_reduce(load(a));
        let y = carry_reduce(load(b));
        store(mul_waves(x, y))
    }
}

/// The F51x4 squaring waves on eight lanes, emitted textually. Limbs in and out
/// are below 2^52.
macro_rules! square_waves_raw_emit {
    ($xe:expr) => {{
        let x: [__m512i; 5] = $xe;

        unsafe {
            // Represent values with coeff. 2
            let mut z1_2 = splat(0);
            let mut z2_2 = splat(0);
            let mut z3_2 = splat(0);
            let mut z4_2 = splat(0);
            let mut z5_2 = splat(0);
            let mut z6_2 = splat(0);
            let mut z7_2 = splat(0);
            let mut z9_2 = splat(0);

            // Represent values with coeff. 4
            let mut z2_4 = splat(0);
            let mut z3_4 = splat(0);
            let mut z4_4 = splat(0);
            let mut z5_4 = splat(0);
            let mut z6_4 = splat(0);
            let mut z7_4 = splat(0);
            let mut z8_4 = splat(0);

            let mut z0_1 = splat(0);
            z0_1 = madd52lo(z0_1, x[0], x[0]);

            let mut z1_1 = splat(0);
            z1_2 = madd52lo(z1_2, x[0], x[1]);
            z1_2 = madd52hi(z1_2, x[0], x[0]);

            z2_4 = madd52hi(z2_4, x[0], x[1]);
            let mut z2_1 = shl!(z2_4, 2);
            z2_2 = madd52lo(z2_2, x[0], x[2]);
            z2_1 = madd52lo(z2_1, x[1], x[1]);

            z3_4 = madd52hi(z3_4, x[0], x[2]);
            let mut z3_1 = shl!(z3_4, 2);
            z3_2 = madd52lo(z3_2, x[1], x[2]);
            z3_2 = madd52lo(z3_2, x[0], x[3]);
            z3_2 = madd52hi(z3_2, x[1], x[1]);

            z4_4 = madd52hi(z4_4, x[1], x[2]);
            z4_4 = madd52hi(z4_4, x[0], x[3]);
            let mut z4_1 = shl!(z4_4, 2);
            z4_2 = madd52lo(z4_2, x[1], x[3]);
            z4_2 = madd52lo(z4_2, x[0], x[4]);
            z4_1 = madd52lo(z4_1, x[2], x[2]);

            z5_4 = madd52hi(z5_4, x[1], x[3]);
            z5_4 = madd52hi(z5_4, x[0], x[4]);
            let mut z5_1 = shl!(z5_4, 2);
            z5_2 = madd52lo(z5_2, x[2], x[3]);
            z5_2 = madd52lo(z5_2, x[1], x[4]);
            z5_2 = madd52hi(z5_2, x[2], x[2]);

            z6_4 = madd52hi(z6_4, x[2], x[3]);
            z6_4 = madd52hi(z6_4, x[1], x[4]);
            let mut z6_1 = shl!(z6_4, 2);
            z6_2 = madd52lo(z6_2, x[2], x[4]);
            z6_1 = madd52lo(z6_1, x[3], x[3]);

            z7_4 = madd52hi(z7_4, x[2], x[4]);
            let mut z7_1 = shl!(z7_4, 2);
            z7_2 = madd52lo(z7_2, x[3], x[4]);
            z7_2 = madd52hi(z7_2, x[3], x[3]);

            z8_4 = madd52hi(z8_4, x[3], x[4]);
            let mut z8_1 = shl!(z8_4, 2);
            z8_1 = madd52lo(z8_1, x[4], x[4]);

            let mut z9_1 = splat(0);
            z9_2 = madd52hi(z9_2, x[4], x[4]);

            z5_1 = add(z5_1, shl!(z5_2, 1));
            z6_1 = add(z6_1, shl!(z6_2, 1));
            z7_1 = add(z7_1, shl!(z7_2, 1));
            z9_1 = add(z9_1, shl!(z9_2, 1));

            let mut t0 = splat(0);
            let mut t1 = splat(0);
            let r19 = splat(19);

            t0 = madd52hi(t0, r19, z9_1);
            t1 = madd52lo(t1, r19, shr!(z9_1, 52));

            z4_2 = madd52lo(z4_2, r19, shr!(z8_1, 52));
            z3_2 = madd52lo(z3_2, r19, shr!(z7_1, 52));
            z2_2 = madd52lo(z2_2, r19, shr!(z6_1, 52));
            z1_2 = madd52lo(z1_2, r19, shr!(z5_1, 52));

            let mut z0_2 = splat(0);
            z0_2 = madd52lo(z0_2, r19, add(t0, t1));
            z1_2 = madd52hi(z1_2, r19, z5_1);
            z2_2 = madd52hi(z2_2, r19, z6_1);
            z3_2 = madd52hi(z3_2, r19, z7_1);
            z4_2 = madd52hi(z4_2, r19, z8_1);

            z0_1 = madd52lo(z0_1, r19, z5_1);
            z1_1 = madd52lo(z1_1, r19, z6_1);
            z2_1 = madd52lo(z2_1, r19, z7_1);
            z3_1 = madd52lo(z3_1, r19, z8_1);
            z4_1 = madd52lo(z4_1, r19, z9_1);

            [
                add(z0_1, add(z0_2, z0_2)),
                add(z1_1, add(z1_2, z1_2)),
                add(z2_1, add(z2_2, z2_2)),
                add(z3_1, add(z3_2, z3_2)),
                add(z4_1, add(z4_2, z4_2)),
            ]
        }
    }};
}

#[target_feature(enable = "avx512ifma")]
unsafe fn square_waves(x: [__m512i; 5]) -> [__m512i; 5] {
    unsafe { carry_reduce(square_waves_raw_emit!(x)) }
}

/// The squaring waves without the trailing carry pass; same bound contract
/// as `mul_waves_raw`.
#[target_feature(enable = "avx512ifma")]
unsafe fn square_waves_raw(x: [__m512i; 5]) -> [__m512i; 5] {
    square_waves_raw_emit!(x)
}

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn square_x8(a: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = carry_reduce(load(a));
        store(square_waves(x))
    }
}

#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn square2_x8(a: &FieldElementX8) -> FieldElementX8 {
    unsafe {
        let x = carry_reduce(load(a));
        let sq = square_waves(x);
        store([
            add(sq[0], sq[0]),
            add(sq[1], sq[1]),
            add(sq[2], sq[2]),
            add(sq[3], sq[3]),
            add(sq[4], sq[4]),
        ])
    }
}

/// `k` successive squarings without leaving the vector domain.
#[target_feature(enable = "avx512ifma")]
pub(crate) unsafe fn pow2k_x8(a: &FieldElementX8, k: u32) -> FieldElementX8 {
    debug_assert!(k > 0);
    unsafe {
        let mut x = carry_reduce(load(a));
        for _ in 0..k {
            x = square_waves(x);
        }
        store(x)
    }
}

// Fused group verification: the whole curve portion of a lane group runs inside
// this one target-feature region, so field values stay in ZMM registers.
// Additions carry-reduce their outputs, so every multiplication operand is
// in-contract for VPMADD52.

pub(crate) mod fused {
    use super::*;
    use crate::backend::lanes::GroupDigits;
    use crate::backend::lanes::edwards_x8::{ExtendedPointX8, LookupTableX8, ProjectiveNielsX8};
    use crate::backend::lanes::field_x8::{FieldElementX8, LANES, LaneMask};
    use crate::backend::serial::u64::constants::{EDWARDS_D, EDWARDS_D2, SQRT_M1};
    use crate::backend::serial::u64::field::FieldElement51;

    type V = [__m512i; 5];

    tf!(
        fn fadd(a: V, b: V) -> V {
            unsafe {
                carry_reduce([
                    add(a[0], b[0]),
                    add(a[1], b[1]),
                    add(a[2], b[2]),
                    add(a[3], b[3]),
                    add(a[4], b[4]),
                ])
            }
        }
    );

    tf!(
        fn fsub(a: V, b: V) -> V {
            unsafe {
                let lo = splat(P_TIMES_16_LO);
                let hi = splat(P_TIMES_16_HI);
                carry_reduce([
                    sub(add(a[0], lo), b[0]),
                    sub(add(a[1], hi), b[1]),
                    sub(add(a[2], hi), b[2]),
                    sub(add(a[3], hi), b[3]),
                    sub(add(a[4], hi), b[4]),
                ])
            }
        }
    );

    tf!(
        fn fmul(a: V, b: V) -> V {
            unsafe { mul_waves(a, b) }
        }
    );

    tf!(
        fn fsquare(a: V) -> V {
            unsafe { square_waves(a) }
        }
    );

    tf!(
        fn fpow2k(a: V, k: u32) -> V {
            unsafe {
                let mut x = a;
                for _ in 0..k {
                    x = square_waves(x);
                }
                x
            }
        }
    );

    // The serial `pow22501` chain, register-resident.
    tf!(
        fn fpow22501(a: V) -> V {
            unsafe {
                let t0 = fsquare(a);
                let t1 = fsquare(fsquare(t0));
                let t2 = fmul(a, t1);
                let t3 = fmul(t0, t2);
                let t4 = fsquare(t3);
                let t5 = fmul(t2, t4);
                let t6 = fpow2k(t5, 5);
                let t7 = fmul(t6, t5);
                let t8 = fpow2k(t7, 10);
                let t9 = fmul(t8, t7);
                let t10 = fpow2k(t9, 20);
                let t11 = fmul(t10, t9);
                let t12 = fpow2k(t11, 10);
                let t13 = fmul(t12, t7);
                let t14 = fpow2k(t13, 50);
                let t15 = fmul(t14, t13);
                let t16 = fpow2k(t15, 100);
                let t17 = fmul(t16, t15);
                let t18 = fpow2k(t17, 50);
                fmul(t18, t13)
            }
        }
    );

    tf!(
        fn fpow_p58(a: V) -> V {
            unsafe {
                let t19 = fpow22501(a);
                let t20 = fpow2k(t19, 2);
                fmul(a, t20)
            }
        }
    );

    // Raw products carry limbs below 18*2^52 < 2^57 and are carry-reduced once,
    // at the next multiply input. The 64p, 128p and 256p biases cover a raw
    // product, a sum of two, and a biased combination; limbs stay below 2^60.

    const P64_LO: u64 = 64 * ((1 << 51) - 19);
    const P64_HI: u64 = 64 * ((1 << 51) - 1);
    const P128_LO: u64 = 128 * ((1 << 51) - 19);
    const P128_HI: u64 = 128 * ((1 << 51) - 1);
    const P256_LO: u64 = 256 * ((1 << 51) - 19);
    const P256_HI: u64 = 256 * ((1 << 51) - 1);

    tf!(
        fn fmul_raw(a: V, b: V) -> V {
            unsafe { mul_waves_raw(a, b) }
        }
    );

    tf!(
        fn fsquare_raw(a: V) -> V {
            unsafe { square_waves_raw(a) }
        }
    );

    tf!(
        fn freduce(a: V) -> V {
            unsafe { carry_reduce(a) }
        }
    );

    tf!(
        /// The canonical representative: limbs below 2^51 holding a value below p,
        /// so two elements agree mod p exactly when their limbs do.
        fn fcanon(a: V) -> V {
            unsafe {
                let mask = splat((1 << 51) - 1);
                let l = carry_reduce(a);
                // The carry out of h + 19 is one exactly when h >= p.
                let mut q = shr!(add(l[0], splat(19)), 51);
                q = shr!(add(l[1], q), 51);
                q = shr!(add(l[2], q), 51);
                q = shr!(add(l[3], q), 51);
                q = shr!(add(l[4], q), 51);
                let r0 = madd52lo(l[0], q, splat(19));
                let r1 = add(l[1], shr!(r0, 51));
                let r2 = add(l[2], shr!(r1, 51));
                let r3 = add(l[3], shr!(r2, 51));
                let r4 = add(l[4], shr!(r3, 51));
                [
                    and(r0, mask),
                    and(r1, mask),
                    and(r2, mask),
                    and(r3, mask),
                    and(r4, mask),
                ]
            }
        }
    );

    tf!(
        /// Lanes where two canonical elements are equal.
        fn fcanon_eq(a: V, b: V) -> u8 {
            unsafe {
                use core::arch::x86_64::_mm512_cmpeq_epi64_mask;
                _mm512_cmpeq_epi64_mask(a[0], b[0])
                    & _mm512_cmpeq_epi64_mask(a[1], b[1])
                    & _mm512_cmpeq_epi64_mask(a[2], b[2])
                    & _mm512_cmpeq_epi64_mask(a[3], b[3])
                    & _mm512_cmpeq_epi64_mask(a[4], b[4])
            }
        }
    );

    tf!(
        /// Lanes that are zero mod p, for limbs of any magnitude.
        fn fis_zero(a: V) -> u8 {
            unsafe { fcanon_eq(fcanon(a), [splat(0); 5]) }
        }
    );

    tf!(
        /// Lane-wise select: `b` where the mask is set, `a` elsewhere.
        fn fblend(k: u8, a: V, b: V) -> V {
            unsafe {
                use core::arch::x86_64::_mm512_mask_blend_epi64;
                [
                    _mm512_mask_blend_epi64(k, a[0], b[0]),
                    _mm512_mask_blend_epi64(k, a[1], b[1]),
                    _mm512_mask_blend_epi64(k, a[2], b[2]),
                    _mm512_mask_blend_epi64(k, a[3], b[3]),
                    _mm512_mask_blend_epi64(k, a[4], b[4]),
                ]
            }
        }
    );

    // Plain limb sums, no reduction.
    tf!(
        fn add_raw(a: V, b: V) -> V {
            unsafe {
                [
                    add(a[0], b[0]),
                    add(a[1], b[1]),
                    add(a[2], b[2]),
                    add(a[3], b[3]),
                    add(a[4], b[4]),
                ]
            }
        }
    );

    // a + bias - b without reduction; the caller picks a bias whose limbs
    // dominate b's.
    tf!(
        fn sub_raw_biased(a: V, b: V, lo: u64, hi: u64) -> V {
            unsafe {
                let lo = splat(lo);
                let hi = splat(hi);
                [
                    sub(add(a[0], lo), b[0]),
                    sub(add(a[1], hi), b[1]),
                    sub(add(a[2], hi), b[2]),
                    sub(add(a[3], hi), b[3]),
                    sub(add(a[4], hi), b[4]),
                ]
            }
        }
    );

    struct ExtV {
        x: V,
        y: V,
        z: V,
        t: V,
    }

    struct ProjV {
        x: V,
        y: V,
        z: V,
    }

    struct ComplV {
        x: V,
        y: V,
        z: V,
        t: V,
    }

    struct NielsV {
        ypx: V,
        ymx: V,
        z: V,
        t2d: V,
    }

    tf!(
        fn load_ext(p: &ExtendedPointX8) -> ExtV {
            unsafe {
                ExtV {
                    x: load(&p.X),
                    y: load(&p.Y),
                    z: load(&p.Z),
                    t: load(&p.T),
                }
            }
        }
    );

    tf!(
        fn load_niels(p: &ProjectiveNielsX8) -> NielsV {
            unsafe {
                NielsV {
                    ypx: load(&p.Y_plus_X),
                    ymx: load(&p.Y_minus_X),
                    z: load(&p.Z),
                    t2d: load(&p.T2d),
                }
            }
        }
    );

    tf!(
        /// Mixed readdition: `p` fields may be raw products (< 2^57), `q` must be
        /// reduced (< 2^52), outputs are raw combinations (< 2^58.2).
        fn readd(p: &ExtV, q: &NielsV) -> ComplV {
            unsafe {
                // Multiply inputs are reduced here, once each.
                let ypx = freduce(add_raw(p.y, p.x)); // < 2^58 before, < 2^52 after
                let ymx = freduce(sub_raw_biased(p.y, p.x, P64_LO, P64_HI));
                let t = freduce(p.t);
                let z = freduce(p.z);
                let pp = fmul_raw(ypx, q.ypx); // < 2^56.2
                let mm = fmul_raw(ymx, q.ymx);
                let tt2d = fmul_raw(t, q.t2d);
                let zz = fmul_raw(z, q.z);
                let zz2 = add_raw(zz, zz); // < 2^57.2
                ComplV {
                    x: sub_raw_biased(pp, mm, P64_LO, P64_HI),    // < 2^57.1
                    y: add_raw(pp, mm),                           // < 2^57.2
                    z: add_raw(zz2, tt2d),                        // < 2^57.8
                    t: sub_raw_biased(zz2, tt2d, P64_LO, P64_HI), // < 2^58.2
                }
            }
        }
    );

    tf!(
        /// Projective doubling: `p` fields may be raw (< 2^57), outputs are raw
        /// combinations (< 2^59.6).
        fn double_proj(p: &ProjV) -> ComplV {
            unsafe {
                let x = freduce(p.x);
                let y = freduce(p.y);
                let z = freduce(p.z);
                let xpy = freduce(add_raw(p.x, p.y));
                let xx = fsquare_raw(x); // < 2^56.2
                let yy = fsquare_raw(y);
                let zz = fsquare_raw(z);
                let xpy_sq = fsquare_raw(xpy);
                let zz2 = add_raw(zz, zz); // < 2^57.2
                let yy_plus_xx = add_raw(yy, xx); // < 2^57.2
                let yy_minus_xx = sub_raw_biased(yy, xx, P64_LO, P64_HI); // < 2^57.1
                ComplV {
                    x: sub_raw_biased(xpy_sq, yy_plus_xx, P128_LO, P128_HI), // < 2^58.4
                    y: yy_plus_xx,
                    z: yy_minus_xx,
                    t: sub_raw_biased(zz2, yy_minus_xx, P256_LO, P256_HI), // < 2^59.4
                }
            }
        }
    );

    tf!(
        /// Completed-to-projective conversion: inputs may be any raw combination
        /// (< 2^60), each reduced once here, and outputs are raw products.
        fn compl_to_proj(p: &ComplV) -> ProjV {
            unsafe {
                let x = freduce(p.x);
                let y = freduce(p.y);
                let z = freduce(p.z);
                let t = freduce(p.t);
                ProjV {
                    x: fmul_raw(x, t),
                    y: fmul_raw(y, z),
                    z: fmul_raw(z, t),
                }
            }
        }
    );

    tf!(
        /// Completed-to-extended conversion, with the same bounds as `compl_to_proj`.
        fn compl_to_ext(p: &ComplV) -> ExtV {
            unsafe {
                let x = freduce(p.x);
                let y = freduce(p.y);
                let z = freduce(p.z);
                let t = freduce(p.t);
                ExtV {
                    x: fmul_raw(x, t),
                    y: fmul_raw(y, z),
                    z: fmul_raw(z, t),
                    t: fmul_raw(x, y),
                }
            }
        }
    );

    /// Decompress eight encodings as `decompress_x8` does, with the square-root
    /// power chain fused and every lane fixup a mask over canonical limbs.
    #[target_feature(enable = "avx512ifma")]
    unsafe fn decompress_fused(encodings: &[[u8; 32]; LANES]) -> (ExtV, u8) {
        unsafe {
            use core::arch::x86_64::_mm512_test_epi64_mask;

            let y_fe = FieldElementX8::from_lanes(&core::array::from_fn(|l| {
                FieldElement51::from_bytes(&encodings[l])
            }));
            let y = load(&y_fe);
            let one = load(&FieldElementX8::ONE);
            let yy = fsquare(y);
            let u = fsub(yy, one); // y^2 - 1
            let v = fadd(fmul(yy, load(&FieldElementX8::splat(EDWARDS_D))), one); // dy^2 + 1

            // sqrt_ratio_i, fused: r = (u v^3)(u v^7)^((p-5)/8), check = v r^2.
            let v3 = fmul(fsquare(v), v);
            let v7 = fmul(fsquare(v3), v);
            let r = fmul(fmul(u, v3), fpow_p58(fmul(u, v7)));
            let check = fmul(v, fsquare(r));

            let sqrt_m1 = load(&FieldElementX8::splat(SQRT_M1));
            let zero = [splat(0); 5];
            let u_neg = fsub(zero, u);

            let c = fcanon(check);
            let correct_sign = fcanon_eq(c, fcanon(u));
            let flipped_sign = fcanon_eq(c, fcanon(u_neg));
            let flipped_sign_i = fcanon_eq(c, fcanon(fmul(u_neg, sqrt_m1)));

            let take_prime = flipped_sign | flipped_sign_i;
            let was_square = correct_sign | flipped_sign;

            let mut x = fblend(take_prime, r, fmul(r, sqrt_m1));
            // A canonical encoding is negative when its low bit is set.
            let x_negative = _mm512_test_epi64_mask(fcanon(x)[0], splat(1));
            x = fblend(x_negative, x, fsub(zero, x));

            let mut sign_bits: u8 = 0;
            for (l, e) in encodings.iter().enumerate() {
                sign_bits |= (e[31] >> 7) << l;
            }
            x = fblend(sign_bits, x, fsub(zero, x));

            // Invalid lanes park at the identity.
            let out = ExtV {
                x: fblend(was_square, zero, x),
                y: fblend(was_square, one, y),
                z: one,
                t: fblend(was_square, zero, fmul(x, y)),
            };

            (out, was_square)
        }
    }

    tf!(
        /// Store a raw extended point as a reduced cached-point table entry.
        fn to_niels_mem(e: &ExtV, d2: V) -> ProjectiveNielsX8 {
            unsafe {
                ProjectiveNielsX8 {
                    Y_plus_X: store(freduce(add_raw(e.y, e.x))),
                    Y_minus_X: store(freduce(sub_raw_biased(e.y, e.x, P64_LO, P64_HI))),
                    Z: store(freduce(e.z)),
                    T2d: store(fmul(freduce(e.t), d2)),
                }
            }
        }
    );

    /// Build the per-lane `[P, 2P, ..., 8P]` table, stored to memory for selection.
    #[target_feature(enable = "avx512ifma")]
    unsafe fn build_table(p: &ExtV) -> LookupTableX8 {
        unsafe {
            let d2 = load(&FieldElementX8::splat(EDWARDS_D2));

            let mut entries = [to_niels_mem(p, d2); 8];
            for j in 1..8 {
                let niels = load_niels(&entries[j - 1]);
                let sum = compl_to_ext(&readd(p, &niels));
                entries[j] = to_niels_mem(&sum, d2);
            }
            LookupTableX8(entries)
        }
    }

    // Vectorized per-lane table selection: the magnitude pick is a three-level
    // blend tree keyed by the index bits, and sign and zero handling are single
    // masked blends, so the whole select stays in vector registers.

    /// Eight-to-one lane-wise multiplexer over preloaded rows.
    #[target_feature(enable = "avx512ifma")]
    #[inline]
    unsafe fn mux8(rows: [__m512i; 8], m0: u8, m1: u8, m2: u8) -> __m512i {
        unsafe {
            use core::arch::x86_64::_mm512_mask_blend_epi64;
            let t01 = _mm512_mask_blend_epi64(m0, rows[0], rows[1]);
            let t23 = _mm512_mask_blend_epi64(m0, rows[2], rows[3]);
            let t45 = _mm512_mask_blend_epi64(m0, rows[4], rows[5]);
            let t67 = _mm512_mask_blend_epi64(m0, rows[6], rows[7]);
            let t0123 = _mm512_mask_blend_epi64(m1, t01, t23);
            let t4567 = _mm512_mask_blend_epi64(m1, t45, t67);
            _mm512_mask_blend_epi64(m2, t0123, t4567)
        }
    }

    macro_rules! mux_coord {
        ($table:expr, $field:ident, $m0:expr, $m1:expr, $m2:expr) => {{
            let mut out = [splat(0); 5];
            let mut i = 0;
            while i < 5 {
                let rows = [
                    _mm512_loadu_si512($table.0[0].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[1].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[2].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[3].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[4].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[5].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[6].$field.limbs[i].as_ptr() as *const _),
                    _mm512_loadu_si512($table.0[7].$field.limbs[i].as_ptr() as *const _),
                ];
                out[i] = mux8(rows, $m0, $m1, $m2);
                i += 1;
            }
            out
        }};
    }

    /// Select, per lane, the cached point for a signed radix-16 digit in
    /// `[-8, 8]`, entirely in vector registers.
    #[target_feature(enable = "avx512ifma")]
    #[inline]
    unsafe fn select_v(table: &LookupTableX8, digits: &[i8; LANES]) -> NielsV {
        unsafe {
            use core::arch::x86_64::_mm512_mask_blend_epi64;

            // Per-lane masks from the digits.
            let mut m0: u8 = 0;
            let mut m1: u8 = 0;
            let mut m2: u8 = 0;
            let mut zero_mask: u8 = 0;
            let mut sign_mask: u8 = 0;
            for (l, &d) in digits.iter().enumerate() {
                if d == 0 {
                    zero_mask |= 1 << l;
                    continue;
                }
                if d < 0 {
                    sign_mask |= 1 << l;
                }
                let idx = d.unsigned_abs() - 1;
                if idx & 1 != 0 {
                    m0 |= 1 << l;
                }
                if idx & 2 != 0 {
                    m1 |= 1 << l;
                }
                if idx & 4 != 0 {
                    m2 |= 1 << l;
                }
            }

            let ypx = mux_coord!(table, Y_plus_X, m0, m1, m2);
            let ymx = mux_coord!(table, Y_minus_X, m0, m1, m2);
            let z = mux_coord!(table, Z, m0, m1, m2);
            let t2d = mux_coord!(table, T2d, m0, m1, m2);

            // Negative digits: swap Y+X with Y-X and negate 2dT, lane-masked.
            let zero_v = [splat(0); 5];
            let neg_t2d = fsub(zero_v, t2d);
            let mut out_ypx = [splat(0); 5];
            let mut out_ymx = [splat(0); 5];
            let mut out_t2d = [splat(0); 5];
            for i in 0..5 {
                out_ypx[i] = _mm512_mask_blend_epi64(sign_mask, ypx[i], ymx[i]);
                out_ymx[i] = _mm512_mask_blend_epi64(sign_mask, ymx[i], ypx[i]);
                out_t2d[i] = _mm512_mask_blend_epi64(sign_mask, t2d[i], neg_t2d[i]);
            }

            // Zero digits: the identity cached point (1, 1, 1, 0).
            let one_limb0 = splat(1);
            let mut out = NielsV {
                ypx: out_ypx,
                ymx: out_ymx,
                z,
                t2d: out_t2d,
            };
            out.ypx[0] = _mm512_mask_blend_epi64(zero_mask, out.ypx[0], one_limb0);
            out.ymx[0] = _mm512_mask_blend_epi64(zero_mask, out.ymx[0], one_limb0);
            out.z[0] = _mm512_mask_blend_epi64(zero_mask, out.z[0], one_limb0);
            out.t2d[0] = _mm512_mask_blend_epi64(zero_mask, out.t2d[0], splat(0));
            for i in 1..5 {
                out.ypx[i] = _mm512_mask_blend_epi64(zero_mask, out.ypx[i], splat(0));
                out.ymx[i] = _mm512_mask_blend_epi64(zero_mask, out.ymx[i], splat(0));
                out.z[i] = _mm512_mask_blend_epi64(zero_mask, out.z[i], splat(0));
                out.t2d[i] = _mm512_mask_blend_epi64(zero_mask, out.t2d[i], splat(0));
            }

            out
        }
    }

    struct AffNielsV {
        ypx: V,
        ymx: V,
        t2d: V,
    }

    tf!(
        /// Affine mixed readdition, with `q.z` one and the same bounds as `readd`.
        /// `p.z` is never multiplied, so it is only doubled raw.
        fn readd_affine(p: &ExtV, q: &AffNielsV) -> ComplV {
            unsafe {
                let ypx = freduce(add_raw(p.y, p.x));
                let ymx = freduce(sub_raw_biased(p.y, p.x, P64_LO, P64_HI));
                let t = freduce(p.t);
                let pp = fmul_raw(ypx, q.ypx);
                let mm = fmul_raw(ymx, q.ymx);
                let tt2d = fmul_raw(t, q.t2d);
                let z2 = add_raw(p.z, p.z); // < 2^58
                ComplV {
                    x: sub_raw_biased(pp, mm, P64_LO, P64_HI),
                    y: add_raw(pp, mm),
                    z: add_raw(z2, tt2d),                        // < 2^58.3
                    t: sub_raw_biased(z2, tt2d, P64_LO, P64_HI), // < 2^58.6
                }
            }
        }
    );

    /// `select_v` for a lane-packed constant table: one permute per limb picks
    /// the entry and its sign at once.
    #[target_feature(enable = "avx512ifma")]
    #[inline]
    unsafe fn select_v_packed(
        table: &crate::backend::lanes::edwards_x8::PackedAffineTableX8,
        digits: &[i8; LANES],
    ) -> AffNielsV {
        unsafe {
            use core::arch::x86_64::{
                _mm512_maskz_permutex2var_epi64, _mm512_mask_blend_epi64,
            };

            // Index `m` reads the entry, `m + 8` the sign-flipped half of
            // the pair each permute is given.
            let mut idx = [0u64; LANES];
            let mut nonzero: u8 = 0;
            for (l, &d) in digits.iter().enumerate() {
                if d == 0 {
                    continue;
                }
                nonzero |= 1 << l;
                let m = (d.unsigned_abs() - 1) as u64;
                idx[l] = if d < 0 { m + 8 } else { m };
            }
            let iv = _mm512_loadu_si512(idx.as_ptr() as *const _);

            let mut out = AffNielsV {
                ypx: [splat(0); 5],
                ymx: [splat(0); 5],
                t2d: [splat(0); 5],
            };
            for i in 0..5 {
                let ypx = _mm512_loadu_si512(table.y_plus_x[i].as_ptr() as *const _);
                let ymx = _mm512_loadu_si512(table.y_minus_x[i].as_ptr() as *const _);
                let t2d = _mm512_loadu_si512(table.t2d[i].as_ptr() as *const _);
                let neg = _mm512_loadu_si512(table.neg_t2d[i].as_ptr() as *const _);
                out.ypx[i] = _mm512_maskz_permutex2var_epi64(nonzero, ypx, iv, ymx);
                out.ymx[i] = _mm512_maskz_permutex2var_epi64(nonzero, ymx, iv, ypx);
                out.t2d[i] = _mm512_maskz_permutex2var_epi64(nonzero, t2d, iv, neg);
            }

            // Zero digits: the affine identity (1, 1, 0), already zero above.
            let one = splat(1);
            out.ypx[0] = _mm512_mask_blend_epi64(nonzero, one, out.ypx[0]);
            out.ymx[0] = _mm512_mask_blend_epi64(nonzero, one, out.ymx[0]);

            out
        }
    }

    /// `select_v` for tables affine in every lane: `Z` is never materialized.
    #[target_feature(enable = "avx512ifma")]
    #[inline]
    unsafe fn select_v_affine(table: &LookupTableX8, digits: &[i8; LANES]) -> AffNielsV {
        unsafe {
            use core::arch::x86_64::_mm512_mask_blend_epi64;

            let mut m0: u8 = 0;
            let mut m1: u8 = 0;
            let mut m2: u8 = 0;
            let mut zero_mask: u8 = 0;
            let mut sign_mask: u8 = 0;
            for (l, &d) in digits.iter().enumerate() {
                if d == 0 {
                    zero_mask |= 1 << l;
                    continue;
                }
                if d < 0 {
                    sign_mask |= 1 << l;
                }
                let idx = d.unsigned_abs() - 1;
                if idx & 1 != 0 {
                    m0 |= 1 << l;
                }
                if idx & 2 != 0 {
                    m1 |= 1 << l;
                }
                if idx & 4 != 0 {
                    m2 |= 1 << l;
                }
            }

            let ypx = mux_coord!(table, Y_plus_X, m0, m1, m2);
            let ymx = mux_coord!(table, Y_minus_X, m0, m1, m2);
            let t2d = mux_coord!(table, T2d, m0, m1, m2);

            let zero_v = [splat(0); 5];
            let neg_t2d = fsub(zero_v, t2d);
            let mut out = AffNielsV {
                ypx: [splat(0); 5],
                ymx: [splat(0); 5],
                t2d: [splat(0); 5],
            };
            for i in 0..5 {
                out.ypx[i] = _mm512_mask_blend_epi64(sign_mask, ypx[i], ymx[i]);
                out.ymx[i] = _mm512_mask_blend_epi64(sign_mask, ymx[i], ypx[i]);
                out.t2d[i] = _mm512_mask_blend_epi64(sign_mask, t2d[i], neg_t2d[i]);
            }

            // Zero digits: the affine identity (1, 1, 0).
            let one_limb0 = splat(1);
            out.ypx[0] = _mm512_mask_blend_epi64(zero_mask, out.ypx[0], one_limb0);
            out.ymx[0] = _mm512_mask_blend_epi64(zero_mask, out.ymx[0], one_limb0);
            out.t2d[0] = _mm512_mask_blend_epi64(zero_mask, out.t2d[0], splat(0));
            for i in 1..5 {
                out.ypx[i] = _mm512_mask_blend_epi64(zero_mask, out.ypx[i], splat(0));
                out.ymx[i] = _mm512_mask_blend_epi64(zero_mask, out.ymx[i], splat(0));
                out.t2d[i] = _mm512_mask_blend_epi64(zero_mask, out.t2d[i], splat(0));
            }

            out
        }
    }

    /// The complete curve stage for one group: decompress, tables, the four-term
    /// lockstep Horner loop, cofactor doublings and identity test.
    ///
    /// # Safety
    ///
    /// Callers must have verified [`available`].
    #[target_feature(enable = "avx512ifma")]
    pub(crate) unsafe fn verify_curve_x8(
        a_encodings: &[[u8; 32]; LANES],
        r_encodings: &[[u8; 32]; LANES],
        prepared_a: Option<&LookupTableX8>,
        digits: &GroupDigits,
        alive_in: &LaneMask,
    ) -> LaneMask {
        unsafe {
            let mut alive = *alive_in;

            // A prepared table carries known-valid affine `A` multiples;
            // otherwise decompress `A` and build its table here.
            let owned_a: Option<LookupTableX8> = match prepared_a {
                Some(_) => None,
                None => {
                    let (A, a_valid) = decompress_fused(a_encodings);
                    for (l, ok) in alive.iter_mut().enumerate() {
                        *ok &= a_valid >> l & 1 == 1;
                    }
                    Some(build_table(&A))
                }
            };

            let (R, r_valid) = decompress_fused(r_encodings);
            for (l, ok) in alive.iter_mut().enumerate() {
                *ok &= r_valid >> l & 1 == 1;
            }

            let table_B = &crate::backend::lanes::edwards_x8::PACKED_TABLE_B;
            let table_B_128 = &crate::backend::lanes::edwards_x8::PACKED_TABLE_B_128;
            let table_R = build_table(&R);

            let mut acc: Option<ProjV> = None;
            let mut last: Option<ComplV> = None;
            for i in (0..=digits.start).rev() {
                let e = match acc {
                    Some(ref p) => {
                        let mut p = ProjV {
                            x: p.x,
                            y: p.y,
                            z: p.z,
                        };
                        for _ in 0..3 {
                            let c = double_proj(&p);
                            p = compl_to_proj(&c);
                        }
                        let c = double_proj(&p);
                        compl_to_ext(&c)
                    }
                    None => load_ext(&ExtendedPointX8::IDENTITY),
                };

                let b_lo_d: [i8; LANES] = core::array::from_fn(|l| digits.b_lo[l][i]);
                let b_hi_d: [i8; LANES] = core::array::from_fn(|l| digits.b_hi[l][i]);
                let a_d: [i8; LANES] = core::array::from_fn(|l| digits.a[l][i]);
                let r_d: [i8; LANES] = core::array::from_fn(|l| digits.r[l][i]);

                let e1 = compl_to_ext(&readd_affine(&e, &select_v_packed(table_B, &b_lo_d)));
                let e2 = compl_to_ext(&readd_affine(&e1, &select_v_packed(table_B_128, &b_hi_d)));
                let e3 = match prepared_a {
                    Some(t) => compl_to_ext(&readd_affine(&e2, &select_v_affine(t, &a_d))),
                    None => compl_to_ext(&readd(
                        &e2,
                        &select_v(owned_a.as_ref().expect("table built above"), &a_d),
                    )),
                };
                let completed = readd(&e3, &select_v(&table_R, &r_d));
                acc = Some(compl_to_proj(&completed));
                last = Some(completed);
            }

            // Three cofactor doublings.
            let e_final = compl_to_ext(&last.expect("loop runs at least one round"));
            let mut p = ProjV {
                x: e_final.x,
                y: e_final.y,
                z: e_final.z,
            };
            for _ in 0..2 {
                let c = double_proj(&p);
                p = compl_to_proj(&c);
            }
            let c = double_proj(&p);
            let checked = compl_to_ext(&c);

            // Identity per lane: X == 0 and Y == Z. `checked` fields are raw
            // (< 2^57); the difference needs the wider bias before reduction.
            let x_zero = fis_zero(checked.x);
            let yz_zero = fis_zero(sub_raw_biased(checked.y, checked.z, P64_LO, P64_HI));

            core::array::from_fn(|l| alive[l] && (x_zero & yz_zero) >> l & 1 == 1)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        // fcanon matches the reduction FieldElement51::to_bytes performs
        #[test]
        fn fcanon_matches_serial_reduction() {
            if !available() {
                return;
            }
            const LOW: u64 = (1u64 << 51) - 1;
            const HI: u64 = (1u64 << 52) - 1;
            let cases: [[u64; 5]; LANES] = [
                [0, 0, 0, 0, 0],
                [1, 0, 0, 0, 0],
                [LOW - 19, LOW, LOW, LOW, LOW], // p - 1
                [LOW - 18, LOW, LOW, LOW, LOW], // p
                [LOW - 17, LOW, LOW, LOW, LOW], // p + 1
                [LOW, LOW, LOW, LOW, LOW],      // 2^255 - 1
                [HI, HI, HI, HI, HI],           // unreduced limbs
                [LOW - 18, LOW, LOW, LOW, LOW - 1],
            ];

            let input = FieldElementX8::from_lanes(&core::array::from_fn(|l| {
                FieldElement51::from_limbs(cases[l])
            }));
            let got = unsafe { store(fcanon(load(&input))) };

            for (l, case) in cases.iter().enumerate() {
                let serial = FieldElement51::from_limbs(*case).to_bytes();
                let want = FieldElement51::from_bytes(&serial).0;
                let have: [u64; 5] = core::array::from_fn(|i| got.limbs[i][l]);
                assert_eq!(have, want, "lane {l}");
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod test {
    use super::*;
    use crate::backend::lanes::field_x8::LANES;
    use crate::backend::serial::u64::field::FieldElement51;

    fn test_elements(seed: u64) -> [FieldElement51; LANES] {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        core::array::from_fn(|_| {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            bytes[31] &= 0x7f;
            FieldElement51::from_bytes(&bytes)
        })
    }

    // every kernel matches the portable lane path, unreduced operands included
    #[test]
    fn kernels_match_portable() {
        if !available() {
            return;
        }

        let a_lanes = test_elements(7);
        let b_lanes = test_elements(9);
        let a = FieldElementX8::from_lanes(&a_lanes);
        let b = FieldElementX8::from_lanes(&b_lanes);
        // Unreduced operands: limb sums near 2^53.
        let wide = {
            let mut w = a;
            for i in 0..5 {
                for l in 0..LANES {
                    w.limbs[i][l] = w.limbs[i][l]
                        .wrapping_add(b.limbs[i][l])
                        .wrapping_add(b.limbs[i][l]);
                }
            }
            w
        };

        let cases = [(&a, &b), (&wide, &b), (&a, &wide), (&wide, &wide)];
        for (i, (x, y)) in cases.iter().enumerate() {
            let via_kernel = unsafe { mul_x8(x, y) }.to_bytes_lanes();
            let via_portable = x.mul(y).to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "mul case {i}");

            let via_kernel = unsafe { add_x8(x, y) }.to_bytes_lanes();
            let via_portable = x.add(y).to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "add case {i}");

            let via_kernel = unsafe { sub_x8(x, y) }.to_bytes_lanes();
            let via_portable = x.sub(y).to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "sub case {i}");

            let via_kernel = unsafe { square_x8(x) }.to_bytes_lanes();
            let via_portable = x.square().to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "square case {i}");

            let via_kernel = unsafe { square2_x8(x) }.to_bytes_lanes();
            let via_portable = x.square2().to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "square2 case {i}");

            let via_kernel = unsafe { neg_x8(x) }.to_bytes_lanes();
            let via_portable = x.neg().to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "neg case {i}");

            let via_kernel = unsafe { pow2k_x8(x, 5) }.to_bytes_lanes();
            let via_portable = x.pow2k(5).to_bytes_lanes();
            assert_eq!(via_kernel, via_portable, "pow2k case {i}");
        }
    }
}
