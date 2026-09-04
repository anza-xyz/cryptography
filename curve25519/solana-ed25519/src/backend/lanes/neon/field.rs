// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.
//
// The lane-per-signature field layer on NEON. The widest vector multiply is
// `umlal` (32x32 -> 64, two lanes), so limbs are radix 2^25.5: ten 32-bit
// limbs, even limbs 26 bits and odd limbs 25. One vector carries two, four or
// eight signatures, never two halves of one field element.

use core::arch::aarch64::*;

use crate::backend::serial::u64::field::FieldElement51;

/// Ten radix-2^25.5 limbs. Even limbs hold 26 bits, odd limbs 25.
pub(crate) type Limbs = [u32; 10];

/// Limb-major staging for up to eight lanes: `stage[i][l]` is limb `i` of lane
/// `l`. Every crossing between vector and per-lane scalar code uses it.
pub(crate) type Stage = [[u32; 8]; 10];

/// An all-zero staging buffer.
pub(crate) const ZERO_STAGE: Stage = [[0u32; 8]; 10];

const M26: u32 = (1 << 26) - 1;
const M25: u32 = (1 << 25) - 1;
const M26_64: u64 = (1 << 26) - 1;
const M25_64: u64 = (1 << 25) - 1;
const M51: u64 = (1 << 51) - 1;

/// Twice the prime, limb-wise: the bias that keeps subtractions nonnegative.
const P2: Limbs = [
    0x7ffffda, 0x3fffffe, 0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe,
    0x7fffffe, 0x3fffffe,
];

/// One radix-2^51 carry pass, so the conversion below can assume 51-bit limbs.
const fn canon51(mut x: [u64; 5]) -> [u64; 5] {
    let mut pass = 0;
    while pass < 2 {
        let c0 = x[0] >> 51;
        x[0] &= M51;
        x[1] += c0;
        let c1 = x[1] >> 51;
        x[1] &= M51;
        x[2] += c1;
        let c2 = x[2] >> 51;
        x[2] &= M51;
        x[3] += c2;
        let c3 = x[3] >> 51;
        x[3] &= M51;
        x[4] += c3;
        let c4 = x[4] >> 51;
        x[4] &= M51;
        x[0] += 19 * c4;
        pass += 1;
    }
    x
}

/// Split radix-2^51 limbs into radix-2^25.5 limbs; no carry crosses a limb.
pub(crate) const fn limbs_from_fe51(x: [u64; 5]) -> Limbs {
    let x = canon51(x);
    [
        (x[0] & M26_64) as u32,
        (x[0] >> 26) as u32,
        (x[1] & M26_64) as u32,
        (x[1] >> 26) as u32,
        (x[2] & M26_64) as u32,
        (x[2] >> 26) as u32,
        (x[3] & M26_64) as u32,
        (x[3] >> 26) as u32,
        (x[4] & M26_64) as u32,
        (x[4] >> 26) as u32,
    ]
}

/// Recombine radix-2^25.5 limbs into radix-2^51, by addition rather than `or`,
/// so limbs a hair over their nominal width still convert exactly.
pub(crate) fn limbs_to_fe51(x: &Limbs) -> FieldElement51 {
    FieldElement51::from_limbs([
        x[0] as u64 + ((x[1] as u64) << 26),
        x[2] as u64 + ((x[3] as u64) << 26),
        x[4] as u64 + ((x[5] as u64) << 26),
        x[6] as u64 + ((x[7] as u64) << 26),
        x[8] as u64 + ((x[9] as u64) << 26),
    ])
}

pub(crate) fn limbs_from_bytes(bytes: &[u8; 32]) -> Limbs {
    limbs_from_fe51(FieldElement51::from_bytes(bytes).0)
}

pub(crate) fn limbs_to_bytes(x: &Limbs) -> [u8; 32] {
    limbs_to_fe51(x).to_bytes()
}

/// Limb-wise negation: `2p - x`, then one carry pass. Valid for reduced `x`.
pub(crate) const fn limbs_neg(x: &Limbs) -> Limbs {
    let mut z = [0u64; 10];
    let mut i = 0;
    while i < 10 {
        z[i] = (P2[i] - x[i]) as u64;
        i += 1;
    }
    reduce_scalar(z)
}

/// The radix-2^25.5 carry chain on 64-bit limbs.
const fn reduce_scalar(mut z: [u64; 10]) -> Limbs {
    macro_rules! carry {
        ($i:expr, 26) => {
            z[$i + 1] += z[$i] >> 26;
            z[$i] &= M26_64;
        };
        ($i:expr, 25) => {
            z[$i + 1] += z[$i] >> 25;
            z[$i] &= M25_64;
        };
    }
    carry!(0, 26);
    carry!(4, 26);
    carry!(1, 25);
    carry!(5, 25);
    carry!(2, 26);
    carry!(6, 26);
    carry!(3, 25);
    carry!(7, 25);
    carry!(4, 26);
    carry!(8, 26);
    z[0] += 19 * (z[9] >> 25);
    z[9] &= M25_64;
    carry!(0, 26);
    [
        z[0] as u32,
        z[1] as u32,
        z[2] as u32,
        z[3] as u32,
        z[4] as u32,
        z[5] as u32,
        z[6] as u32,
        z[7] as u32,
        z[8] as u32,
        z[9] as u32,
    ]
}

// `Simd` wraps the NEON intrinsics a radix-2^25.5 kernel needs one to one, so
// the multiply below is written once and instantiated at both register widths.
// Every method is a single instruction except the two marked otherwise.

pub(crate) trait Simd: Copy {
    /// Signature lanes carried by one vector.
    const W: usize;
    /// The widened accumulator for `W` lanes.
    type Acc: Copy;

    fn splat(v: u32) -> Self;
    /// Load `W` consecutive `u32`.
    ///
    /// # Safety
    ///
    /// `p` must be readable for `W` `u32`.
    unsafe fn load(p: *const u32) -> Self;
    /// Store `W` consecutive `u32`.
    ///
    /// # Safety
    ///
    /// `p` must be writable for `W` `u32`.
    unsafe fn store(self, p: *mut u32);

    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn and26(self) -> Self;
    fn and25(self) -> Self;
    fn shr26(self) -> Self;
    fn shr25(self) -> Self;
    fn shl1(self) -> Self;
    fn shl2(self) -> Self;
    fn mul19(self) -> Self;

    fn acc_zero() -> Self::Acc;
    fn mull(x: Self, y: Self) -> Self::Acc;
    fn mlal(a: Self::Acc, x: Self, y: Self) -> Self::Acc;
    fn acc_and26(a: Self::Acc) -> Self::Acc;
    fn acc_and25(a: Self::Acc) -> Self::Acc;
    /// `a + (b >> 26)`.
    fn acc_sra26(a: Self::Acc, b: Self::Acc) -> Self::Acc;
    /// `a + (b >> 25)`.
    fn acc_sra25(a: Self::Acc, b: Self::Acc) -> Self::Acc;
    /// `a + 19 * (b >> 25)`; four instructions.
    fn acc_wrap19(a: Self::Acc, b: Self::Acc) -> Self::Acc;
    fn narrow(a: Self::Acc) -> Self;
}

impl Simd for uint32x2_t {
    const W: usize = 2;
    type Acc = uint64x2_t;

    #[inline(always)]
    fn splat(v: u32) -> Self {
        unsafe { vdup_n_u32(v) }
    }
    #[inline(always)]
    unsafe fn load(p: *const u32) -> Self {
        unsafe { vld1_u32(p) }
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u32) {
        unsafe { vst1_u32(p, self) }
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        unsafe { vadd_u32(self, o) }
    }
    #[inline(always)]
    fn sub(self, o: Self) -> Self {
        unsafe { vsub_u32(self, o) }
    }
    #[inline(always)]
    fn and26(self) -> Self {
        unsafe { vand_u32(self, vdup_n_u32(M26)) }
    }
    #[inline(always)]
    fn and25(self) -> Self {
        unsafe { vand_u32(self, vdup_n_u32(M25)) }
    }
    #[inline(always)]
    fn shr26(self) -> Self {
        unsafe { vshr_n_u32::<26>(self) }
    }
    #[inline(always)]
    fn shr25(self) -> Self {
        unsafe { vshr_n_u32::<25>(self) }
    }
    #[inline(always)]
    fn shl1(self) -> Self {
        unsafe { vshl_n_u32::<1>(self) }
    }
    #[inline(always)]
    fn shl2(self) -> Self {
        unsafe { vshl_n_u32::<2>(self) }
    }
    #[inline(always)]
    fn mul19(self) -> Self {
        unsafe { vmul_n_u32(self, 19) }
    }

    #[inline(always)]
    fn acc_zero() -> Self::Acc {
        unsafe { vdupq_n_u64(0) }
    }
    #[inline(always)]
    fn mull(x: Self, y: Self) -> Self::Acc {
        unsafe { vmull_u32(x, y) }
    }
    #[inline(always)]
    fn mlal(a: Self::Acc, x: Self, y: Self) -> Self::Acc {
        unsafe { vmlal_u32(a, x, y) }
    }
    #[inline(always)]
    fn acc_and26(a: Self::Acc) -> Self::Acc {
        unsafe { vandq_u64(a, vdupq_n_u64(M26_64)) }
    }
    #[inline(always)]
    fn acc_and25(a: Self::Acc) -> Self::Acc {
        unsafe { vandq_u64(a, vdupq_n_u64(M25_64)) }
    }
    #[inline(always)]
    fn acc_sra26(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe { vsraq_n_u64::<26>(a, b) }
    }
    #[inline(always)]
    fn acc_sra25(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe { vsraq_n_u64::<25>(a, b) }
    }
    #[inline(always)]
    fn acc_wrap19(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe {
            let t = vshrq_n_u64::<25>(b);
            let t19 = vaddq_u64(vshlq_n_u64::<4>(t), vaddq_u64(vshlq_n_u64::<1>(t), t));
            vaddq_u64(a, t19)
        }
    }
    #[inline(always)]
    fn narrow(a: Self::Acc) -> Self {
        unsafe { vmovn_u64(a) }
    }
}

impl Simd for uint32x4_t {
    const W: usize = 4;
    type Acc = [uint64x2_t; 2];

    #[inline(always)]
    fn splat(v: u32) -> Self {
        unsafe { vdupq_n_u32(v) }
    }
    #[inline(always)]
    unsafe fn load(p: *const u32) -> Self {
        unsafe { vld1q_u32(p) }
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u32) {
        unsafe { vst1q_u32(p, self) }
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        unsafe { vaddq_u32(self, o) }
    }
    #[inline(always)]
    fn sub(self, o: Self) -> Self {
        unsafe { vsubq_u32(self, o) }
    }
    #[inline(always)]
    fn and26(self) -> Self {
        unsafe { vandq_u32(self, vdupq_n_u32(M26)) }
    }
    #[inline(always)]
    fn and25(self) -> Self {
        unsafe { vandq_u32(self, vdupq_n_u32(M25)) }
    }
    #[inline(always)]
    fn shr26(self) -> Self {
        unsafe { vshrq_n_u32::<26>(self) }
    }
    #[inline(always)]
    fn shr25(self) -> Self {
        unsafe { vshrq_n_u32::<25>(self) }
    }
    #[inline(always)]
    fn shl1(self) -> Self {
        unsafe { vshlq_n_u32::<1>(self) }
    }
    #[inline(always)]
    fn shl2(self) -> Self {
        unsafe { vshlq_n_u32::<2>(self) }
    }
    #[inline(always)]
    fn mul19(self) -> Self {
        unsafe { vmulq_n_u32(self, 19) }
    }

    #[inline(always)]
    fn acc_zero() -> Self::Acc {
        unsafe { [vdupq_n_u64(0), vdupq_n_u64(0)] }
    }
    #[inline(always)]
    fn mull(x: Self, y: Self) -> Self::Acc {
        unsafe {
            [
                vmull_u32(vget_low_u32(x), vget_low_u32(y)),
                vmull_high_u32(x, y),
            ]
        }
    }
    #[inline(always)]
    fn mlal(a: Self::Acc, x: Self, y: Self) -> Self::Acc {
        unsafe {
            [
                vmlal_u32(a[0], vget_low_u32(x), vget_low_u32(y)),
                vmlal_high_u32(a[1], x, y),
            ]
        }
    }
    #[inline(always)]
    fn acc_and26(a: Self::Acc) -> Self::Acc {
        unsafe {
            let m = vdupq_n_u64(M26_64);
            [vandq_u64(a[0], m), vandq_u64(a[1], m)]
        }
    }
    #[inline(always)]
    fn acc_and25(a: Self::Acc) -> Self::Acc {
        unsafe {
            let m = vdupq_n_u64(M25_64);
            [vandq_u64(a[0], m), vandq_u64(a[1], m)]
        }
    }
    #[inline(always)]
    fn acc_sra26(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe { [vsraq_n_u64::<26>(a[0], b[0]), vsraq_n_u64::<26>(a[1], b[1])] }
    }
    #[inline(always)]
    fn acc_sra25(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe { [vsraq_n_u64::<25>(a[0], b[0]), vsraq_n_u64::<25>(a[1], b[1])] }
    }
    #[inline(always)]
    fn acc_wrap19(a: Self::Acc, b: Self::Acc) -> Self::Acc {
        unsafe {
            let t0 = vshrq_n_u64::<25>(b[0]);
            let t1 = vshrq_n_u64::<25>(b[1]);
            [
                vaddq_u64(
                    a[0],
                    vaddq_u64(vshlq_n_u64::<4>(t0), vaddq_u64(vshlq_n_u64::<1>(t0), t0)),
                ),
                vaddq_u64(
                    a[1],
                    vaddq_u64(vshlq_n_u64::<4>(t1), vaddq_u64(vshlq_n_u64::<1>(t1), t1)),
                ),
            ]
        }
    }
    #[inline(always)]
    fn narrow(a: Self::Acc) -> Self {
        unsafe { vmovn_high_u64(vmovn_u64(a[0]), a[1]) }
    }
}

/// `S::W` independent field elements in radix 2^25.5, limb-major: `l[i]`
/// holds limb `i` of every lane.
#[derive(Copy, Clone)]
pub(crate) struct Fe<S: Simd>(pub(crate) [S; 10]);

/// The carry chain on widened accumulators, narrowing back to 32-bit limbs, in
/// two interleaved halves so the chain is not one long dependency.
#[inline(always)]
fn reduce_acc<S: Simd>(z: &mut [S::Acc; 10]) -> [S; 10] {
    macro_rules! carry {
        ($i:expr, 26) => {
            z[$i + 1] = S::acc_sra26(z[$i + 1], z[$i]);
            z[$i] = S::acc_and26(z[$i]);
        };
        ($i:expr, 25) => {
            z[$i + 1] = S::acc_sra25(z[$i + 1], z[$i]);
            z[$i] = S::acc_and25(z[$i]);
        };
    }
    carry!(0, 26);
    carry!(4, 26);
    carry!(1, 25);
    carry!(5, 25);
    carry!(2, 26);
    carry!(6, 26);
    carry!(3, 25);
    carry!(7, 25);
    carry!(4, 26);
    carry!(8, 26);
    z[0] = S::acc_wrap19(z[0], z[9]);
    z[9] = S::acc_and25(z[9]);
    carry!(0, 26);

    [
        S::narrow(z[0]),
        S::narrow(z[1]),
        S::narrow(z[2]),
        S::narrow(z[3]),
        S::narrow(z[4]),
        S::narrow(z[5]),
        S::narrow(z[6]),
        S::narrow(z[7]),
        S::narrow(z[8]),
        S::narrow(z[9]),
    ]
}

/// The same chain on 32-bit limbs, for sums and differences that never leave
/// `u32`.
#[inline(always)]
fn reduce32<S: Simd>(mut z: [S; 10]) -> [S; 10] {
    macro_rules! carry {
        ($i:expr, 26) => {
            z[$i + 1] = z[$i + 1].add(z[$i].shr26());
            z[$i] = z[$i].and26();
        };
        ($i:expr, 25) => {
            z[$i + 1] = z[$i + 1].add(z[$i].shr25());
            z[$i] = z[$i].and25();
        };
    }
    carry!(0, 26);
    carry!(4, 26);
    carry!(1, 25);
    carry!(5, 25);
    carry!(2, 26);
    carry!(6, 26);
    carry!(3, 25);
    carry!(7, 25);
    carry!(4, 26);
    carry!(8, 26);
    let c = z[9].shr25();
    z[9] = z[9].and25();
    z[0] = z[0].add(c.mul19());
    carry!(0, 26);
    z
}

impl<S: Simd> Fe<S> {
    #[inline(always)]
    pub(crate) fn splat(l: &Limbs) -> Self {
        Fe([
            S::splat(l[0]),
            S::splat(l[1]),
            S::splat(l[2]),
            S::splat(l[3]),
            S::splat(l[4]),
            S::splat(l[5]),
            S::splat(l[6]),
            S::splat(l[7]),
            S::splat(l[8]),
            S::splat(l[9]),
        ])
    }

    #[inline(always)]
    pub(crate) fn zero() -> Self {
        Fe([S::splat(0); 10])
    }

    #[inline(always)]
    pub(crate) fn one() -> Self {
        let mut v = [S::splat(0); 10];
        v[0] = S::splat(1);
        Fe(v)
    }

    /// Gather lanes `off .. off + W` of a staging buffer.
    #[inline(always)]
    pub(crate) fn from_stage_off(s: &Stage, off: usize) -> Self {
        debug_assert!(off + S::W <= 8);
        unsafe {
            Fe([
                S::load(s[0].as_ptr().add(off)),
                S::load(s[1].as_ptr().add(off)),
                S::load(s[2].as_ptr().add(off)),
                S::load(s[3].as_ptr().add(off)),
                S::load(s[4].as_ptr().add(off)),
                S::load(s[5].as_ptr().add(off)),
                S::load(s[6].as_ptr().add(off)),
                S::load(s[7].as_ptr().add(off)),
                S::load(s[8].as_ptr().add(off)),
                S::load(s[9].as_ptr().add(off)),
            ])
        }
    }

    #[inline(always)]
    pub(crate) fn to_stage_off(self, s: &mut Stage, off: usize) {
        debug_assert!(off + S::W <= 8);
        unsafe {
            for i in 0..10 {
                self.0[i].store(s[i].as_mut_ptr().add(off));
            }
        }
    }

    #[inline(always)]
    pub(crate) fn add(self, o: Self) -> Self {
        let mut z = [S::splat(0); 10];
        for i in 0..10 {
            z[i] = self.0[i].add(o.0[i]);
        }
        Fe(reduce32::<S>(z))
    }

    /// Limb-wise `self + 2p - o`; `2p` dominates any reduced operand.
    #[inline(always)]
    pub(crate) fn sub(self, o: Self) -> Self {
        let mut z = [S::splat(0); 10];
        for i in 0..10 {
            z[i] = self.0[i].add(S::splat(P2[i])).sub(o.0[i]);
        }
        Fe(reduce32::<S>(z))
    }

    #[inline(always)]
    pub(crate) fn neg(self) -> Self {
        Fe::zero().sub(self)
    }

    #[inline(always)]
    pub(crate) fn mul(self, o: Self) -> Self {
        let x = &self.0;
        let y = &o.0;

        let y1_19 = y[1].mul19();
        let y2_19 = y[2].mul19();
        let y3_19 = y[3].mul19();
        let y4_19 = y[4].mul19();
        let y5_19 = y[5].mul19();
        let y6_19 = y[6].mul19();
        let y7_19 = y[7].mul19();
        let y8_19 = y[8].mul19();
        let y9_19 = y[9].mul19();

        let x1_2 = x[1].shl1();
        let x3_2 = x[3].shl1();
        let x5_2 = x[5].shl1();
        let x7_2 = x[7].shl1();
        let x9_2 = x[9].shl1();

        let mut z = [S::acc_zero(); 10];

        z[0] = S::mull(x[0], y[0]);
        z[0] = S::mlal(z[0], x1_2, y9_19);
        z[0] = S::mlal(z[0], x[2], y8_19);
        z[0] = S::mlal(z[0], x3_2, y7_19);
        z[0] = S::mlal(z[0], x[4], y6_19);
        z[0] = S::mlal(z[0], x5_2, y5_19);
        z[0] = S::mlal(z[0], x[6], y4_19);
        z[0] = S::mlal(z[0], x7_2, y3_19);
        z[0] = S::mlal(z[0], x[8], y2_19);
        z[0] = S::mlal(z[0], x9_2, y1_19);

        z[1] = S::mull(x[0], y[1]);
        z[1] = S::mlal(z[1], x[1], y[0]);
        z[1] = S::mlal(z[1], x[2], y9_19);
        z[1] = S::mlal(z[1], x[3], y8_19);
        z[1] = S::mlal(z[1], x[4], y7_19);
        z[1] = S::mlal(z[1], x[5], y6_19);
        z[1] = S::mlal(z[1], x[6], y5_19);
        z[1] = S::mlal(z[1], x[7], y4_19);
        z[1] = S::mlal(z[1], x[8], y3_19);
        z[1] = S::mlal(z[1], x[9], y2_19);

        z[2] = S::mull(x[0], y[2]);
        z[2] = S::mlal(z[2], x1_2, y[1]);
        z[2] = S::mlal(z[2], x[2], y[0]);
        z[2] = S::mlal(z[2], x3_2, y9_19);
        z[2] = S::mlal(z[2], x[4], y8_19);
        z[2] = S::mlal(z[2], x5_2, y7_19);
        z[2] = S::mlal(z[2], x[6], y6_19);
        z[2] = S::mlal(z[2], x7_2, y5_19);
        z[2] = S::mlal(z[2], x[8], y4_19);
        z[2] = S::mlal(z[2], x9_2, y3_19);

        z[3] = S::mull(x[0], y[3]);
        z[3] = S::mlal(z[3], x[1], y[2]);
        z[3] = S::mlal(z[3], x[2], y[1]);
        z[3] = S::mlal(z[3], x[3], y[0]);
        z[3] = S::mlal(z[3], x[4], y9_19);
        z[3] = S::mlal(z[3], x[5], y8_19);
        z[3] = S::mlal(z[3], x[6], y7_19);
        z[3] = S::mlal(z[3], x[7], y6_19);
        z[3] = S::mlal(z[3], x[8], y5_19);
        z[3] = S::mlal(z[3], x[9], y4_19);

        z[4] = S::mull(x[0], y[4]);
        z[4] = S::mlal(z[4], x1_2, y[3]);
        z[4] = S::mlal(z[4], x[2], y[2]);
        z[4] = S::mlal(z[4], x3_2, y[1]);
        z[4] = S::mlal(z[4], x[4], y[0]);
        z[4] = S::mlal(z[4], x5_2, y9_19);
        z[4] = S::mlal(z[4], x[6], y8_19);
        z[4] = S::mlal(z[4], x7_2, y7_19);
        z[4] = S::mlal(z[4], x[8], y6_19);
        z[4] = S::mlal(z[4], x9_2, y5_19);

        z[5] = S::mull(x[0], y[5]);
        z[5] = S::mlal(z[5], x[1], y[4]);
        z[5] = S::mlal(z[5], x[2], y[3]);
        z[5] = S::mlal(z[5], x[3], y[2]);
        z[5] = S::mlal(z[5], x[4], y[1]);
        z[5] = S::mlal(z[5], x[5], y[0]);
        z[5] = S::mlal(z[5], x[6], y9_19);
        z[5] = S::mlal(z[5], x[7], y8_19);
        z[5] = S::mlal(z[5], x[8], y7_19);
        z[5] = S::mlal(z[5], x[9], y6_19);

        z[6] = S::mull(x[0], y[6]);
        z[6] = S::mlal(z[6], x1_2, y[5]);
        z[6] = S::mlal(z[6], x[2], y[4]);
        z[6] = S::mlal(z[6], x3_2, y[3]);
        z[6] = S::mlal(z[6], x[4], y[2]);
        z[6] = S::mlal(z[6], x5_2, y[1]);
        z[6] = S::mlal(z[6], x[6], y[0]);
        z[6] = S::mlal(z[6], x7_2, y9_19);
        z[6] = S::mlal(z[6], x[8], y8_19);
        z[6] = S::mlal(z[6], x9_2, y7_19);

        z[7] = S::mull(x[0], y[7]);
        z[7] = S::mlal(z[7], x[1], y[6]);
        z[7] = S::mlal(z[7], x[2], y[5]);
        z[7] = S::mlal(z[7], x[3], y[4]);
        z[7] = S::mlal(z[7], x[4], y[3]);
        z[7] = S::mlal(z[7], x[5], y[2]);
        z[7] = S::mlal(z[7], x[6], y[1]);
        z[7] = S::mlal(z[7], x[7], y[0]);
        z[7] = S::mlal(z[7], x[8], y9_19);
        z[7] = S::mlal(z[7], x[9], y8_19);

        z[8] = S::mull(x[0], y[8]);
        z[8] = S::mlal(z[8], x1_2, y[7]);
        z[8] = S::mlal(z[8], x[2], y[6]);
        z[8] = S::mlal(z[8], x3_2, y[5]);
        z[8] = S::mlal(z[8], x[4], y[4]);
        z[8] = S::mlal(z[8], x5_2, y[3]);
        z[8] = S::mlal(z[8], x[6], y[2]);
        z[8] = S::mlal(z[8], x7_2, y[1]);
        z[8] = S::mlal(z[8], x[8], y[0]);
        z[8] = S::mlal(z[8], x9_2, y9_19);

        z[9] = S::mull(x[0], y[9]);
        z[9] = S::mlal(z[9], x[1], y[8]);
        z[9] = S::mlal(z[9], x[2], y[7]);
        z[9] = S::mlal(z[9], x[3], y[6]);
        z[9] = S::mlal(z[9], x[4], y[5]);
        z[9] = S::mlal(z[9], x[5], y[4]);
        z[9] = S::mlal(z[9], x[6], y[3]);
        z[9] = S::mlal(z[9], x[7], y[2]);
        z[9] = S::mlal(z[9], x[8], y[1]);
        z[9] = S::mlal(z[9], x[9], y[0]);

        Fe(reduce_acc::<S>(&mut z))
    }

    /// Squaring with the symmetric products folded: pair `(i, j)` with `i < j`
    /// contributes twice, and a pair of odd indices twice again from the radix.
    #[inline(always)]
    pub(crate) fn square(self) -> Self {
        let x = &self.0;

        let x0_2 = x[0].shl1();
        let x1_2 = x[1].shl1();
        let x2_2 = x[2].shl1();
        let x3_2 = x[3].shl1();
        let x4_2 = x[4].shl1();
        let x5_2 = x[5].shl1();
        let x6_2 = x[6].shl1();
        let x7_2 = x[7].shl1();
        let x1_4 = x[1].shl2();
        let x3_4 = x[3].shl2();
        let x5_4 = x[5].shl2();
        let x7_4 = x[7].shl2();

        let x5_19 = x[5].mul19();
        let x6_19 = x[6].mul19();
        let x7_19 = x[7].mul19();
        let x8_19 = x[8].mul19();
        let x9_19 = x[9].mul19();

        let mut z = [S::acc_zero(); 10];

        // k = 0: x0^2 + 19(4 x1x9 + 2 x2x8 + 4 x3x7 + 2 x4x6 + 2 x5^2)
        z[0] = S::mull(x[0], x[0]);
        z[0] = S::mlal(z[0], x1_4, x9_19);
        z[0] = S::mlal(z[0], x2_2, x8_19);
        z[0] = S::mlal(z[0], x3_4, x7_19);
        z[0] = S::mlal(z[0], x4_2, x6_19);
        z[0] = S::mlal(z[0], x[5], x5_19.shl1());

        // k = 1: 2 x0x1 + 19(2 x2x9 + 2 x3x8 + 2 x4x7 + 2 x5x6)
        z[1] = S::mull(x0_2, x[1]);
        z[1] = S::mlal(z[1], x2_2, x9_19);
        z[1] = S::mlal(z[1], x3_2, x8_19);
        z[1] = S::mlal(z[1], x4_2, x7_19);
        z[1] = S::mlal(z[1], x5_2, x6_19);

        // k = 2: 2 x0x2 + 2 x1^2 + 19(4 x3x9 + 2 x4x8 + 4 x5x7 + x6^2)
        z[2] = S::mull(x0_2, x[2]);
        z[2] = S::mlal(z[2], x1_2, x[1]);
        z[2] = S::mlal(z[2], x3_4, x9_19);
        z[2] = S::mlal(z[2], x4_2, x8_19);
        z[2] = S::mlal(z[2], x5_4, x7_19);
        z[2] = S::mlal(z[2], x[6], x6_19);

        // k = 3: 2 x0x3 + 2 x1x2 + 19(2 x4x9 + 2 x5x8 + 2 x6x7)
        z[3] = S::mull(x0_2, x[3]);
        z[3] = S::mlal(z[3], x1_2, x[2]);
        z[3] = S::mlal(z[3], x4_2, x9_19);
        z[3] = S::mlal(z[3], x5_2, x8_19);
        z[3] = S::mlal(z[3], x6_2, x7_19);

        // k = 4: 2 x0x4 + 4 x1x3 + x2^2 + 19(4 x5x9 + 2 x6x8 + 2 x7^2)
        z[4] = S::mull(x0_2, x[4]);
        z[4] = S::mlal(z[4], x1_4, x[3]);
        z[4] = S::mlal(z[4], x[2], x[2]);
        z[4] = S::mlal(z[4], x5_4, x9_19);
        z[4] = S::mlal(z[4], x6_2, x8_19);
        z[4] = S::mlal(z[4], x[7], x7_19.shl1());

        // k = 5: 2 x0x5 + 2 x1x4 + 2 x2x3 + 19(2 x6x9 + 2 x7x8)
        z[5] = S::mull(x0_2, x[5]);
        z[5] = S::mlal(z[5], x1_2, x[4]);
        z[5] = S::mlal(z[5], x2_2, x[3]);
        z[5] = S::mlal(z[5], x6_2, x9_19);
        z[5] = S::mlal(z[5], x7_2, x8_19);

        // k = 6: 2 x0x6 + 4 x1x5 + 2 x2x4 + 2 x3^2 + 19(4 x7x9 + x8^2)
        z[6] = S::mull(x0_2, x[6]);
        z[6] = S::mlal(z[6], x1_4, x[5]);
        z[6] = S::mlal(z[6], x2_2, x[4]);
        z[6] = S::mlal(z[6], x3_2, x[3]);
        z[6] = S::mlal(z[6], x7_4, x9_19);
        z[6] = S::mlal(z[6], x[8], x8_19);

        // k = 7: 2 x0x7 + 2 x1x6 + 2 x2x5 + 2 x3x4 + 19(2 x8x9)
        z[7] = S::mull(x0_2, x[7]);
        z[7] = S::mlal(z[7], x1_2, x[6]);
        z[7] = S::mlal(z[7], x2_2, x[5]);
        z[7] = S::mlal(z[7], x3_2, x[4]);
        z[7] = S::mlal(z[7], x8_19, x[9].shl1());

        // k = 8: 2 x0x8 + 4 x1x7 + 2 x2x6 + 4 x3x5 + x4^2 + 19(2 x9^2)
        z[8] = S::mull(x0_2, x[8]);
        z[8] = S::mlal(z[8], x1_4, x[7]);
        z[8] = S::mlal(z[8], x2_2, x[6]);
        z[8] = S::mlal(z[8], x3_4, x[5]);
        z[8] = S::mlal(z[8], x[4], x[4]);
        z[8] = S::mlal(z[8], x[9], x9_19.shl1());

        // k = 9: 2 x0x9 + 2 x1x8 + 2 x2x7 + 2 x3x6 + 2 x4x5
        z[9] = S::mull(x0_2, x[9]);
        z[9] = S::mlal(z[9], x1_2, x[8]);
        z[9] = S::mlal(z[9], x2_2, x[7]);
        z[9] = S::mlal(z[9], x3_2, x[6]);
        z[9] = S::mlal(z[9], x4_2, x[5]);

        Fe(reduce_acc::<S>(&mut z))
    }

    #[inline(always)]
    pub(crate) fn square2(self) -> Self {
        let s = self.square();
        s.add(s)
    }

    #[inline(always)]
    pub(crate) fn pow2k(self, k: u32) -> Self {
        debug_assert!(k > 0);
        let mut x = self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn fe51_elements(seed: u64) -> [FieldElement51; 8] {
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

    fn stage_from(fes: &[FieldElement51; 8]) -> Stage {
        let mut s = ZERO_STAGE;
        for (l, fe) in fes.iter().enumerate() {
            let limbs = limbs_from_fe51(fe.0);
            for i in 0..10 {
                s[i][l] = limbs[i];
            }
        }
        s
    }

    fn lane_bytes(s: &Stage, l: usize) -> [u8; 32] {
        let limbs: Limbs = core::array::from_fn(|i| s[i][l]);
        limbs_to_bytes(&limbs)
    }

    fn check_ops<S: Simd>() {
        let a_fe = fe51_elements(11);
        let b_fe = fe51_elements(22);
        let sa = stage_from(&a_fe);
        let sb = stage_from(&b_fe);

        for off in [0usize, 8 - S::W] {
            let a = Fe::<S>::from_stage_off(&sa, off);
            let b = Fe::<S>::from_stage_off(&sb, off);

            let mut out = ZERO_STAGE;
            let cases: [(Fe<S>, &str); 6] = [
                (a.add(b), "add"),
                (a.sub(b), "sub"),
                (a.mul(b), "mul"),
                (a.square(), "square"),
                (a.square2(), "square2"),
                (a.neg(), "neg"),
            ];
            for (value, what) in cases {
                value.to_stage_off(&mut out, off);
                for l in 0..S::W {
                    let x = &a_fe[off + l];
                    let y = &b_fe[off + l];
                    let expected = match what {
                        "add" => x + y,
                        "sub" => x - y,
                        "mul" => x * y,
                        "square" => x.square(),
                        "square2" => x.square2(),
                        _ => -x,
                    };
                    assert_eq!(
                        lane_bytes(&out, off + l),
                        expected.to_bytes(),
                        "{what} lane {l} at offset {off}"
                    );
                }
            }

            let p = a.pow2k(7);
            p.to_stage_off(&mut out, off);
            for l in 0..S::W {
                assert_eq!(
                    lane_bytes(&out, off + l),
                    a_fe[off + l].pow2k(7).to_bytes(),
                    "pow2k lane {l} at offset {off}"
                );
            }
        }
    }

    // two-lane field ops match the serial element
    #[test]
    fn field_ops_match_serial_x2() {
        check_ops::<uint32x2_t>();
    }

    // four-lane field ops match the serial element
    #[test]
    fn field_ops_match_serial_x4() {
        check_ops::<uint32x4_t>();
    }

    // radix-2^51 limbs survive the trip through radix-2^25.5 and back
    #[test]
    fn limb_conversions_round_trip() {
        for fe in fe51_elements(33) {
            let limbs = limbs_from_fe51(fe.0);
            assert_eq!(limbs_to_bytes(&limbs), fe.to_bytes());
            assert_eq!(limbs_from_bytes(&fe.to_bytes()), limbs);
            assert_eq!(limbs_to_bytes(&limbs_neg(&limbs)), (-&fe).to_bytes());
        }
    }
}
