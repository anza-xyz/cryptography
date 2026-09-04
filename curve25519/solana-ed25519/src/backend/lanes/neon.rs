// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.

//! The AArch64 half of the wide-lane verifier.
//!
//! NEON has no widening 64x64 multiply, so limbs are radix 2^25.5 in 32-bit
//! lanes. A NEON register holds fewer than eight of them, so [`Width`] selects
//! the lane count and the pipeline is generic over the field vector.

pub(crate) mod curve;
pub(crate) mod field;

use super::GroupDigits;
use super::edwards_x8::LookupTableX8;
use super::field_x8::{LANES, LaneMask};

/// Signature lanes per vector.
///
/// `X4` fills a NEON register exactly, `X2` uses its 64-bit halves, and `X8`
/// interleaves two `X4` blocks.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Width {
    X2,
    X4,
    X8,
}

impl Width {
    pub(crate) fn lanes(self) -> usize {
        match self {
            Width::X2 => 2,
            Width::X4 => 4,
            Width::X8 => 8,
        }
    }
}

/// The width the lane path uses on AArch64.
pub(crate) const DEFAULT_WIDTH: Width = Width::X8;

/// The curve stage for one group of eight, run `Width::lanes()` signatures at
/// a time.
pub(crate) fn verify_curve_neon(
    a_encodings: &[[u8; 32]; LANES],
    r_encodings: &[[u8; 32]; LANES],
    prepared_a: Option<&LookupTableX8>,
    digits: &GroupDigits,
    alive: &LaneMask,
    width: Width,
) -> LaneMask {
    // A prepared table arrives in the portable radix-2^51 layout; convert it
    // once for the whole group rather than once per sub-batch.
    let prepared = prepared_a.map(curve::TableMem::from_lookup_table_x8);
    let prepared = prepared.as_ref();

    let mut out = [false; LANES];
    let w = width.lanes();
    let mut off = 0;
    while off < LANES {
        let verdicts = match width {
            Width::X2 => curve::verify_curve::<curve::Fe2>(
                a_encodings,
                r_encodings,
                prepared,
                digits,
                alive,
                off,
            ),
            Width::X4 => curve::verify_curve::<curve::Fe4>(
                a_encodings,
                r_encodings,
                prepared,
                digits,
                alive,
                off,
            ),
            Width::X8 => curve::verify_curve::<curve::Fe8>(
                a_encodings,
                r_encodings,
                prepared,
                digits,
                alive,
                off,
            ),
        };
        out[off..off + w].copy_from_slice(&verdicts[off..off + w]);
        off += w;
    }
    out
}

/// Field-multiply throughput at one lane width, against the same number of
/// lanes' worth of serial radix-2^51 multiplications. Benches only.
///
/// Four independent chains per round, so it measures throughput, not latency.
pub(crate) fn field_mul_probe(width: Option<Width>, rounds: usize) -> u32 {
    use crate::backend::serial::u64::field::FieldElement51;
    use curve::{Fe2, Fe4, Fe8, Field};
    use field::{Stage, ZERO_STAGE, limbs_from_bytes};

    fn seed_stage() -> Stage {
        let mut s = ZERO_STAGE;
        for l in 0..LANES {
            let mut bytes = [0u8; 32];
            bytes[0] = 3 + l as u8;
            bytes[9] = 0x5a;
            bytes[20] = 0xc3;
            let limbs = limbs_from_bytes(&bytes);
            for (i, limb) in limbs.iter().enumerate() {
                s[i][l] = *limb;
            }
        }
        s
    }

    fn run<F: Field>(s: &Stage, rounds: usize) -> u32 {
        let b = F::from_stage(s, 0);
        let mut a = [b, b.add(F::one()), b.square(), b.add(b)];
        for _ in 0..rounds {
            for x in a.iter_mut() {
                *x = x.mul(b);
            }
        }
        let mut out = ZERO_STAGE;
        let mut acc = 0u32;
        for x in a {
            x.to_stage(&mut out, 0);
            acc = acc.wrapping_add(out[0][0]);
        }
        acc
    }

    let s = seed_stage();
    match width {
        Some(Width::X2) => run::<Fe2>(&s, rounds),
        Some(Width::X4) => run::<Fe4>(&s, rounds),
        Some(Width::X8) => run::<Fe8>(&s, rounds),
        None => {
            // Eight serial elements, four independent chains each, so the
            // work matches one X8 round exactly.
            let mut bytes = [0u8; 32];
            bytes[0] = 3;
            bytes[9] = 0x5a;
            bytes[20] = 0xc3;
            let b = FieldElement51::from_bytes(&bytes);
            let mut a = [[b; 4]; LANES];
            for lane in a.iter_mut() {
                lane[1] = &lane[1] + &FieldElement51::ONE;
                lane[2] = lane[2].square();
                lane[3] = &lane[3] + &lane[3];
            }
            for _ in 0..rounds {
                for lane in a.iter_mut() {
                    for x in lane.iter_mut() {
                        *x = &*x * &b;
                    }
                }
            }
            let mut acc = 0u32;
            for lane in a {
                for x in lane {
                    acc = acc.wrapping_add(x.to_bytes()[0] as u32);
                }
            }
            acc
        }
    }
}
