// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.

//! Lane-per-signature verification backend.
//!
//! One independent signature per SIMD lane: eight verification equations
//! advance in lockstep, each with its own verdict, and no field operation
//! ever crosses lanes.

pub(crate) mod digits;
pub(crate) mod edwards_x8;
pub(crate) mod field_x8;
#[cfg(curve25519_backend = "simd")]
pub(crate) mod ifma_x8;
pub(crate) mod joint;
mod joint_data;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub(crate) mod neon;
#[cfg(curve25519_backend = "simd")]
pub(crate) mod sha512_x8;

use digits::HEEA_DIGITS;
use field_x8::LANES;

/// The per-lane radix-16 digit schedules of the HEEA-transformed verification equation.
pub(crate) struct GroupDigits {
    /// Joint fixed-base table index per lane, one row per position.
    pub(crate) b: [[u64; LANES]; HEEA_DIGITS],
    /// Digits applied to A, with the HEEA sign folded in.
    pub(crate) a: [[i8; HEEA_DIGITS]; LANES],
    /// Digits applied to R.
    pub(crate) r: [[i8; HEEA_DIGITS]; LANES],
    /// Highest position with any nonzero digit.
    pub(crate) start: usize,
}
