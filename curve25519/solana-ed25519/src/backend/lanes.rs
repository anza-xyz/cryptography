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

pub(crate) mod edwards_x8;
pub(crate) mod field_x8;
#[cfg(curve25519_backend = "simd")]
pub(crate) mod ifma_x8;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub(crate) mod neon;
#[cfg(curve25519_backend = "simd")]
pub(crate) mod sha512_x8;

/// Number of radix-16 digit positions a 129-bit scalar can occupy.
pub(crate) const HEEA_DIGITS: usize = 33;

/// The per-lane radix-16 digit schedules of the four MSM terms of the
/// HEEA-transformed verification equation.
pub(crate) struct GroupDigits {
    /// Digits of \\(\tau s \bmod 2^{128}\\), applied to \\(B\\).
    pub(crate) b_lo: [[i8; HEEA_DIGITS]; field_x8::LANES],
    /// Digits of \\(\lfloor \tau s / 2^{128} \rfloor\\), applied to \\(B'\\).
    pub(crate) b_hi: [[i8; HEEA_DIGITS]; field_x8::LANES],
    /// Digits applied to \\(A\\): \\(\pm\rho\\) with the HEEA sign folded in.
    pub(crate) a: [[i8; HEEA_DIGITS]; field_x8::LANES],
    /// Digits applied to \\(R\\): \\(-\tau\\).
    pub(crate) r: [[i8; HEEA_DIGITS]; field_x8::LANES],
    /// Highest digit position with any nonzero digit.
    pub(crate) start: usize,
}
