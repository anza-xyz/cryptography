// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.
//
// The curve stage of one lane group on AArch64, written once over a generic
// field vector so every NEON lane width runs the same code.

#![allow(non_snake_case)]

use core::arch::aarch64::{uint32x2_t, uint32x4_t};

use super::field::{
    Fe, Limbs, Simd, Stage, ZERO_STAGE, limbs_from_bytes, limbs_from_fe51, limbs_neg,
    limbs_to_bytes,
};
use crate::backend::lanes::edwards_x8::LookupTableX8;
use crate::backend::lanes::field_x8::{LANES, LaneMask};
use crate::backend::lanes::{GroupDigits, HEEA_DIGITS};
use crate::backend::serial::curve_models::AffineNielsPoint;
use crate::backend::serial::u64::constants::{
    EDWARDS_D, EDWARDS_D2, LANE_BASEPOINT_128_MULTIPLES, LANE_BASEPOINT_MULTIPLES, SQRT_M1,
};

const D: Limbs = limbs_from_fe51(EDWARDS_D.0);
const D2: Limbs = limbs_from_fe51(EDWARDS_D2.0);
const SQRT_MINUS_ONE: Limbs = limbs_from_fe51(SQRT_M1.0);

/// The field-vector interface the curve layer is written against.
pub(crate) trait Field: Copy {
    /// Signature lanes carried.
    const W: usize;

    fn zero() -> Self;
    fn one() -> Self;
    fn splat(l: &Limbs) -> Self;
    /// Gather lanes `off .. off + W` of a staging buffer.
    fn from_stage(s: &Stage, off: usize) -> Self;
    /// Scatter to lanes `off .. off + W` of a staging buffer.
    fn to_stage(self, s: &mut Stage, off: usize);

    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn square(self) -> Self;
    fn square2(self) -> Self;
    fn neg(self) -> Self;
    fn pow2k(self, k: u32) -> Self;
}

impl<S: Simd> Field for Fe<S> {
    const W: usize = S::W;

    #[inline(always)]
    fn zero() -> Self {
        Fe::zero()
    }
    #[inline(always)]
    fn one() -> Self {
        Fe::one()
    }
    #[inline(always)]
    fn splat(l: &Limbs) -> Self {
        Fe::splat(l)
    }
    #[inline(always)]
    fn from_stage(s: &Stage, off: usize) -> Self {
        Fe::from_stage_off(s, off)
    }
    #[inline(always)]
    fn to_stage(self, s: &mut Stage, off: usize) {
        Fe::to_stage_off(self, s, off)
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        Fe::add(self, o)
    }
    #[inline(always)]
    fn sub(self, o: Self) -> Self {
        Fe::sub(self, o)
    }
    #[inline(always)]
    fn mul(self, o: Self) -> Self {
        Fe::mul(self, o)
    }
    #[inline(always)]
    fn square(self) -> Self {
        Fe::square(self)
    }
    #[inline(always)]
    fn square2(self) -> Self {
        Fe::square2(self)
    }
    #[inline(always)]
    fn neg(self) -> Self {
        Fe::neg(self)
    }
    #[inline(always)]
    fn pow2k(self, k: u32) -> Self {
        Fe::pow2k(self, k)
    }
}

/// Two lanes per vector, from the 64-bit halves of a NEON register.
pub(crate) type Fe2 = Fe<uint32x2_t>;
/// Four lanes per vector: one full register, one `umlal` pair per product.
pub(crate) type Fe4 = Fe<uint32x4_t>;

/// Eight lanes as two interleaved four-lane blocks, so every operation issues
/// two independent instruction streams.
#[derive(Copy, Clone)]
pub(crate) struct Fe8 {
    lo: Fe4,
    hi: Fe4,
}

impl Field for Fe8 {
    const W: usize = 8;

    #[inline(always)]
    fn zero() -> Self {
        Fe8 {
            lo: Fe4::zero(),
            hi: Fe4::zero(),
        }
    }
    #[inline(always)]
    fn one() -> Self {
        Fe8 {
            lo: Fe4::one(),
            hi: Fe4::one(),
        }
    }
    #[inline(always)]
    fn splat(l: &Limbs) -> Self {
        Fe8 {
            lo: Fe4::splat(l),
            hi: Fe4::splat(l),
        }
    }
    #[inline(always)]
    fn from_stage(s: &Stage, off: usize) -> Self {
        debug_assert_eq!(off, 0);
        Fe8 {
            lo: Fe4::from_stage_off(s, 0),
            hi: Fe4::from_stage_off(s, 4),
        }
    }
    #[inline(always)]
    fn to_stage(self, s: &mut Stage, off: usize) {
        debug_assert_eq!(off, 0);
        self.lo.to_stage_off(s, 0);
        self.hi.to_stage_off(s, 4);
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        Fe8 {
            lo: self.lo.add(o.lo),
            hi: self.hi.add(o.hi),
        }
    }
    #[inline(always)]
    fn sub(self, o: Self) -> Self {
        Fe8 {
            lo: self.lo.sub(o.lo),
            hi: self.hi.sub(o.hi),
        }
    }
    #[inline(always)]
    fn mul(self, o: Self) -> Self {
        Fe8 {
            lo: self.lo.mul(o.lo),
            hi: self.hi.mul(o.hi),
        }
    }
    #[inline(always)]
    fn square(self) -> Self {
        Fe8 {
            lo: self.lo.square(),
            hi: self.hi.square(),
        }
    }
    #[inline(always)]
    fn square2(self) -> Self {
        Fe8 {
            lo: self.lo.square2(),
            hi: self.hi.square2(),
        }
    }
    #[inline(always)]
    fn neg(self) -> Self {
        Fe8 {
            lo: self.lo.neg(),
            hi: self.hi.neg(),
        }
    }
    #[inline(always)]
    fn pow2k(self, k: u32) -> Self {
        Fe8 {
            lo: self.lo.pow2k(k),
            hi: self.hi.pow2k(k),
        }
    }
}

// Points. Lanes never interact, so these are the serial formulas applied to
// wide elements.

#[derive(Copy, Clone)]
struct ExtP<F> {
    X: F,
    Y: F,
    Z: F,
    T: F,
}

#[derive(Copy, Clone)]
struct ProjP<F> {
    X: F,
    Y: F,
    Z: F,
}

#[derive(Copy, Clone)]
struct ComplP<F> {
    X: F,
    Y: F,
    Z: F,
    T: F,
}

#[derive(Copy, Clone)]
struct NielsP<F> {
    ypx: F,
    ymx: F,
    Z: F,
    t2d: F,
}

#[derive(Copy, Clone)]
struct AffNielsP<F> {
    ypx: F,
    ymx: F,
    t2d: F,
}

#[inline(always)]
fn readd<F: Field>(p: &ExtP<F>, q: &NielsP<F>) -> ComplP<F> {
    let ypx = p.Y.add(p.X);
    let ymx = p.Y.sub(p.X);
    let pp = ypx.mul(q.ypx);
    let mm = ymx.mul(q.ymx);
    let tt2d = p.T.mul(q.t2d);
    let zz = p.Z.mul(q.Z);
    let zz2 = zz.add(zz);
    ComplP {
        X: pp.sub(mm),
        Y: pp.add(mm),
        Z: zz2.add(tt2d),
        T: zz2.sub(tt2d),
    }
}

/// Readdition against an entry whose `Z` is one in every lane.
#[inline(always)]
fn readd_affine<F: Field>(p: &ExtP<F>, q: &AffNielsP<F>) -> ComplP<F> {
    let ypx = p.Y.add(p.X);
    let ymx = p.Y.sub(p.X);
    let pp = ypx.mul(q.ypx);
    let mm = ymx.mul(q.ymx);
    let tt2d = p.T.mul(q.t2d);
    let zz2 = p.Z.add(p.Z);
    ComplP {
        X: pp.sub(mm),
        Y: pp.add(mm),
        Z: zz2.add(tt2d),
        T: zz2.sub(tt2d),
    }
}

#[inline(always)]
fn double_proj<F: Field>(p: &ProjP<F>) -> ComplP<F> {
    let XX = p.X.square();
    let YY = p.Y.square();
    let ZZ2 = p.Z.square2();
    let X_plus_Y_sq = p.X.add(p.Y).square();
    let YY_plus_XX = YY.add(XX);
    let YY_minus_XX = YY.sub(XX);
    ComplP {
        X: X_plus_Y_sq.sub(YY_plus_XX),
        Y: YY_plus_XX,
        Z: YY_minus_XX,
        T: ZZ2.sub(YY_minus_XX),
    }
}

#[inline(always)]
fn compl_to_proj<F: Field>(p: &ComplP<F>) -> ProjP<F> {
    ProjP {
        X: p.X.mul(p.T),
        Y: p.Y.mul(p.Z),
        Z: p.Z.mul(p.T),
    }
}

#[inline(always)]
fn compl_to_ext<F: Field>(p: &ComplP<F>) -> ExtP<F> {
    ExtP {
        X: p.X.mul(p.T),
        Y: p.Y.mul(p.Z),
        Z: p.Z.mul(p.T),
        T: p.X.mul(p.Y),
    }
}

#[inline(always)]
fn to_niels<F: Field>(e: &ExtP<F>) -> NielsP<F> {
    NielsP {
        ypx: e.Y.add(e.X),
        ymx: e.Y.sub(e.X),
        Z: e.Z,
        t2d: e.T.mul(F::splat(&D2)),
    }
}

fn identity_ext<F: Field>() -> ExtP<F> {
    ExtP {
        X: F::zero(),
        Y: F::one(),
        Z: F::one(),
        T: F::zero(),
    }
}

// Per-lane crossings. Sign choices, validity and the identity test are per-lane
// predicates on canonical encodings, so they go through the staging layout and
// the serial byte conversion.

/// Canonical encodings of lanes `off .. off + W`.
fn lane_bytes<F: Field>(x: F, off: usize) -> [[u8; 32]; LANES] {
    let mut s = ZERO_STAGE;
    x.to_stage(&mut s, off);
    let mut out = [[0u8; 32]; LANES];
    for (l, o) in out.iter_mut().enumerate().skip(off).take(F::W) {
        let limbs: Limbs = core::array::from_fn(|i| s[i][l]);
        *o = limbs_to_bytes(&limbs);
    }
    out
}

/// Keep `a` where the mask is false, take `b` where it is true.
fn blend<F: Field>(a: F, b: F, take_b: &LaneMask, off: usize) -> F {
    let mut sa = ZERO_STAGE;
    let mut sb = ZERO_STAGE;
    a.to_stage(&mut sa, off);
    b.to_stage(&mut sb, off);
    for l in off..off + F::W {
        if take_b[l] {
            for i in 0..10 {
                sa[i][l] = sb[i][l];
            }
        }
    }
    F::from_stage(&sa, off)
}

fn pow22501<F: Field>(x: F) -> F {
    let t0 = x.square();
    let t1 = t0.square().square();
    let t2 = x.mul(t1);
    let t3 = t0.mul(t2);
    let t4 = t3.square();
    let t5 = t2.mul(t4);
    let t6 = t5.pow2k(5);
    let t7 = t6.mul(t5);
    let t8 = t7.pow2k(10);
    let t9 = t8.mul(t7);
    let t10 = t9.pow2k(20);
    let t11 = t10.mul(t9);
    let t12 = t11.pow2k(10);
    let t13 = t12.mul(t7);
    let t14 = t13.pow2k(50);
    let t15 = t14.mul(t13);
    let t16 = t15.pow2k(100);
    let t17 = t16.mul(t15);
    let t18 = t17.pow2k(50);
    t18.mul(t13)
}

fn pow_p58<F: Field>(x: F) -> F {
    let t19 = pow22501(x);
    let t20 = t19.pow2k(2);
    x.mul(t20)
}

/// `sqrt(u/v)` per lane, with the serial `sqrt_ratio_i` conventions.
fn sqrt_ratio_i<F: Field>(u: F, v: F, off: usize) -> (LaneMask, F) {
    let sqrt_m1 = F::splat(&SQRT_MINUS_ONE);

    let v3 = v.square().mul(v);
    let v7 = v3.square().mul(v);
    let r = u.mul(v3).mul(pow_p58(u.mul(v7)));
    let check = v.mul(r.square());

    let u_neg = u.neg();
    let u_neg_i = u_neg.mul(sqrt_m1);

    let check_bytes = lane_bytes(check, off);
    let u_bytes = lane_bytes(u, off);
    let u_neg_bytes = lane_bytes(u_neg, off);
    let u_neg_i_bytes = lane_bytes(u_neg_i, off);

    let mut correct_sign = [false; LANES];
    let mut flipped_sign = [false; LANES];
    let mut flipped_sign_i = [false; LANES];
    for l in off..off + F::W {
        correct_sign[l] = check_bytes[l] == u_bytes[l];
        flipped_sign[l] = check_bytes[l] == u_neg_bytes[l];
        flipped_sign_i[l] = check_bytes[l] == u_neg_i_bytes[l];
    }

    let take_prime: LaneMask = core::array::from_fn(|l| flipped_sign[l] || flipped_sign_i[l]);
    let mut r = blend(r, r.mul(sqrt_m1), &take_prime, off);

    // The nonnegative root.
    let r_bytes = lane_bytes(r, off);
    let is_negative: LaneMask = core::array::from_fn(|l| r_bytes[l][0] & 1 == 1);
    r = blend(r, r.neg(), &is_negative, off);

    let was_square: LaneMask = core::array::from_fn(|l| correct_sign[l] || flipped_sign[l]);
    (was_square, r)
}

/// Decompress lanes `off .. off + W` with ZIP-215 semantics; invalid lanes
/// are parked at the identity so the pipeline stays well formed.
fn decompress<F: Field>(encodings: &[[u8; 32]; LANES], off: usize) -> (ExtP<F>, LaneMask) {
    let mut s = ZERO_STAGE;
    for l in off..off + F::W {
        let limbs = limbs_from_bytes(&encodings[l]);
        for i in 0..10 {
            s[i][l] = limbs[i];
        }
    }
    let Y = F::from_stage(&s, off);
    let Z = F::one();
    let YY = Y.square();
    let u = YY.sub(Z);
    let v = YY.mul(F::splat(&D)).add(Z);
    let (is_valid, X) = sqrt_ratio_i(u, v, off);

    let sign_bits: LaneMask = core::array::from_fn(|l| encodings[l][31] >> 7 == 1);
    let X = blend(X, X.neg(), &sign_bits, off);
    let T = X.mul(Y);

    let id = identity_ext::<F>();
    let point = ExtP {
        X: blend(id.X, X, &is_valid, off),
        Y: blend(id.Y, Y, &is_valid, off),
        Z: blend(id.Z, Z, &is_valid, off),
        T: blend(id.T, T, &is_valid, off),
    };
    (point, is_valid)
}

// Lookup tables. Entries live in the staging layout because the digit that
// picks one is a per-lane value, so a select is a scalar gather feeding one
// vector load per limb. Both signs of `2dT` are stored, covering negative
// digits from the same gather.

#[derive(Copy, Clone)]
pub(crate) struct NielsMem {
    ypx: Stage,
    ymx: Stage,
    Z: Stage,
    t2d: Stage,
    t2d_neg: Stage,
}

const EMPTY_NIELS: NielsMem = NielsMem {
    ypx: ZERO_STAGE,
    ymx: ZERO_STAGE,
    Z: ZERO_STAGE,
    t2d: ZERO_STAGE,
    t2d_neg: ZERO_STAGE,
};

/// `[P, 2P, ..., 8P]` per lane, for signed radix-16 digits in `[-8, 8]`.
pub(crate) struct TableMem(pub(crate) [NielsMem; 8]);

impl TableMem {
    pub(crate) fn empty() -> TableMem {
        TableMem([EMPTY_NIELS; 8])
    }

    /// Convert a table the portable path built, keeping all eight lanes.
    pub(crate) fn from_lookup_table_x8(t: &LookupTableX8) -> TableMem {
        let mut out = TableMem::empty();
        for (j, entry) in out.0.iter_mut().enumerate() {
            for l in 0..LANES {
                let src = &t.0[j];
                let ypx = limbs_from_fe51(src.Y_plus_X.lane(l).0);
                let ymx = limbs_from_fe51(src.Y_minus_X.lane(l).0);
                let z = limbs_from_fe51(src.Z.lane(l).0);
                let t2d = limbs_from_fe51(src.T2d.lane(l).0);
                let t2d_neg = limbs_neg(&t2d);
                for i in 0..10 {
                    entry.ypx[i][l] = ypx[i];
                    entry.ymx[i][l] = ymx[i];
                    entry.Z[i][l] = z[i];
                    entry.t2d[i][l] = t2d[i];
                    entry.t2d_neg[i][l] = t2d_neg[i];
                }
            }
        }
        out
    }
}

fn store_niels<F: Field>(n: &NielsP<F>, out: &mut NielsMem, off: usize) {
    n.ypx.to_stage(&mut out.ypx, off);
    n.ymx.to_stage(&mut out.ymx, off);
    n.Z.to_stage(&mut out.Z, off);
    n.t2d.to_stage(&mut out.t2d, off);
    n.t2d.neg().to_stage(&mut out.t2d_neg, off);
}

fn build_table<F: Field>(P: &ExtP<F>, off: usize) -> TableMem {
    let mut out = TableMem::empty();
    let mut cur = to_niels(P);
    store_niels(&cur, &mut out.0[0], off);
    for j in 1..8 {
        let sum = compl_to_ext(&readd(P, &cur));
        cur = to_niels(&sum);
        store_niels(&cur, &mut out.0[j], off);
    }
    out
}

fn select<F: Field>(t: &TableMem, digits: &[[i8; HEEA_DIGITS]; LANES], i: usize, off: usize) -> NielsP<F> {
    let mut sy = ZERO_STAGE;
    let mut sm = ZERO_STAGE;
    let mut sz = ZERO_STAGE;
    let mut st = ZERO_STAGE;
    for l in off..off + F::W {
        let d = digits[l][i];
        if d == 0 {
            // The identity cached point (1, 1, 1, 0).
            sy[0][l] = 1;
            sm[0][l] = 1;
            sz[0][l] = 1;
            continue;
        }
        let e = &t.0[(d.unsigned_abs() as usize) - 1];
        let neg = d < 0;
        let (a, b) = if neg { (&e.ymx, &e.ypx) } else { (&e.ypx, &e.ymx) };
        let td = if neg { &e.t2d_neg } else { &e.t2d };
        for k in 0..10 {
            sy[k][l] = a[k][l];
            sm[k][l] = b[k][l];
            sz[k][l] = e.Z[k][l];
            st[k][l] = td[k][l];
        }
    }
    NielsP {
        ypx: F::from_stage(&sy, off),
        ymx: F::from_stage(&sm, off),
        Z: F::from_stage(&sz, off),
        t2d: F::from_stage(&st, off),
    }
}

/// A static affine table entry: the same point in every lane, `Z` implicit.
struct AffMem {
    ypx: Limbs,
    ymx: Limbs,
    t2d: Limbs,
    t2d_neg: Limbs,
}

const fn aff_entry(e: &AffineNielsPoint) -> AffMem {
    let t2d = limbs_from_fe51(e.xy2d.0);
    AffMem {
        ypx: limbs_from_fe51(e.y_plus_x.0),
        ymx: limbs_from_fe51(e.y_minus_x.0),
        t2d,
        t2d_neg: limbs_neg(&t2d),
    }
}

const fn aff_table(src: &[AffineNielsPoint; 8]) -> [AffMem; 8] {
    [
        aff_entry(&src[0]),
        aff_entry(&src[1]),
        aff_entry(&src[2]),
        aff_entry(&src[3]),
        aff_entry(&src[4]),
        aff_entry(&src[5]),
        aff_entry(&src[6]),
        aff_entry(&src[7]),
    ]
}

static NEON_TABLE_B: [AffMem; 8] = aff_table(&LANE_BASEPOINT_MULTIPLES);
static NEON_TABLE_B_128: [AffMem; 8] = aff_table(&LANE_BASEPOINT_128_MULTIPLES);

fn select_affine<F: Field>(
    t: &[AffMem; 8],
    digits: &[[i8; HEEA_DIGITS]; LANES],
    i: usize,
    off: usize,
) -> AffNielsP<F> {
    let mut sy = ZERO_STAGE;
    let mut sm = ZERO_STAGE;
    let mut st = ZERO_STAGE;
    for l in off..off + F::W {
        let d = digits[l][i];
        if d == 0 {
            // The affine identity (1, 1, 0).
            sy[0][l] = 1;
            sm[0][l] = 1;
            continue;
        }
        let e = &t[(d.unsigned_abs() as usize) - 1];
        let neg = d < 0;
        let (a, b) = if neg { (&e.ymx, &e.ypx) } else { (&e.ypx, &e.ymx) };
        let td = if neg { &e.t2d_neg } else { &e.t2d };
        for k in 0..10 {
            sy[k][l] = a[k];
            sm[k][l] = b[k];
            st[k][l] = td[k];
        }
    }
    AffNielsP {
        ypx: F::from_stage(&sy, off),
        ymx: F::from_stage(&sm, off),
        t2d: F::from_stage(&st, off),
    }
}

/// Verify lanes `off .. off + F::W` of one prepared group. Verdicts land at
/// the same absolute lane positions; the rest of the returned mask is false.
pub(crate) fn verify_curve<F: Field>(
    a_encodings: &[[u8; 32]; LANES],
    r_encodings: &[[u8; 32]; LANES],
    prepared_a: Option<&TableMem>,
    digits: &GroupDigits,
    alive_in: &LaneMask,
    off: usize,
) -> LaneMask {
    let mut alive = *alive_in;

    let owned_a: Option<TableMem> = match prepared_a {
        Some(_) => None,
        None => {
            let (A, a_valid) = decompress::<F>(a_encodings, off);
            for l in off..off + F::W {
                alive[l] &= a_valid[l];
            }
            Some(build_table(&A, off))
        }
    };
    let table_A = prepared_a.unwrap_or_else(|| owned_a.as_ref().expect("table built above"));

    let (R, r_valid) = decompress::<F>(r_encodings, off);
    for l in off..off + F::W {
        alive[l] &= r_valid[l];
    }
    let table_R = build_table(&R, off);

    let mut acc: Option<ProjP<F>> = None;
    let mut last: Option<ComplP<F>> = None;
    for i in (0..=digits.start).rev() {
        let e = match acc {
            Some(ref p) => {
                let mut p = *p;
                for _ in 0..3 {
                    p = compl_to_proj(&double_proj(&p));
                }
                compl_to_ext(&double_proj(&p))
            }
            None => identity_ext::<F>(),
        };

        let e1 = compl_to_ext(&readd_affine(
            &e,
            &select_affine::<F>(&NEON_TABLE_B, &digits.b_lo, i, off),
        ));
        let e2 = compl_to_ext(&readd_affine(
            &e1,
            &select_affine::<F>(&NEON_TABLE_B_128, &digits.b_hi, i, off),
        ));
        let e3 = compl_to_ext(&readd(&e2, &select::<F>(table_A, &digits.a, i, off)));
        let completed = readd(&e3, &select::<F>(&table_R, &digits.r, i, off));
        acc = Some(compl_to_proj(&completed));
        last = Some(completed);
    }

    // Three cofactor doublings, then the identity test.
    let e_final = compl_to_ext(&last.expect("loop runs at least one round"));
    let mut p = ProjP {
        X: e_final.X,
        Y: e_final.Y,
        Z: e_final.Z,
    };
    for _ in 0..2 {
        p = compl_to_proj(&double_proj(&p));
    }
    let checked = compl_to_ext(&double_proj(&p));

    let x_bytes = lane_bytes(checked.X, off);
    let yz_bytes = lane_bytes(checked.Y.sub(checked.Z), off);

    let mut out = [false; LANES];
    for l in off..off + F::W {
        out[l] = alive[l] && x_bytes[l] == [0u8; 32] && yz_bytes[l] == [0u8; 32];
    }
    out
}
