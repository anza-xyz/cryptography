// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2018 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! The `u64` backend uses `u64`s and a `(u64, u64) -> u128` multiplier.
//!
//! On x86_64, the idiom `(x as u128) * (y as u128)` lowers to `MUL`
//! instructions taking 64-bit inputs and producing 128-bit outputs.  On
//! wasm32, which has no such instruction, the product is built from four
//! 32-bit multiplies instead.  On other platforms, this implementation is
//! not recommended.
//!
//! On Haswell and newer, the BMI2 extension provides `MULX`, and on
//! Broadwell and newer, the ADX extension provides `ADCX` and `ADOX`
//! (allowing the CPU to compute two carry chains in parallel).  These
//! will be used if available.

pub mod field;

/// Variable-time field inversion for public data.
pub(crate) mod inversion;

pub mod scalar;

pub mod constants;

/// Multiply two 64-bit integers with 128 bits of output.
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    // `mul_split` needs this. Checking it on every target lets native test
    // runs cover the bound at each call site. All callers stay below 2^60.
    debug_assert!(x < 1 << 63 && y < 1 << 63);
    if cfg!(target_arch = "wasm32") {
        mul_split(x, y)
    } else {
        (x as u128) * (y as u128)
    }
}

/// Multiply two integers below 2^63 with 128 bits of output, using only
/// 32x32->64 multiplies.
///
/// On wasm32, `(x as u128) * (y as u128)` is a call to the `__multi3`
/// libcall, which does a full 128x128-bit multiply. Each product here is a
/// single `i64.mul`, and only 32-bit values are ever multiplied, which is the
/// same constant-time assumption the 32-bit backend of curve25519-dalek makes.
#[inline(always)]
fn mul_split(x: u64, y: u64) -> u128 {
    const LO: u64 = 0xffff_ffff;
    let (x0, x1) = (x & LO, x >> 32);
    let (y0, y1) = (y & LO, y >> 32);

    let ll = x0 * y0;
    // x1, y1 < 2^31, so this cannot overflow.
    let mid = x0 * y1 + x1 * y0;
    let hh = x1 * y1;

    let t = (ll >> 32) + (mid & LO);
    let lo = (ll & LO) | (t << 32);
    let hi = hh + (mid >> 32) + (t >> 32);
    ((hi as u128) << 64) | (lo as u128)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Largest field limb accepted by multiplication.
    const LIMB_MAX: u64 = (1 << 54) - 1;

    #[test]
    fn mul_split_edge_cases() {
        let values = [
            0,
            1,
            LIMB_MAX,
            19 * LIMB_MAX,
            0xffff_ffff,
            1 << 32,
            (1 << 63) - 1,
        ];
        for x in values {
            for y in values {
                assert_eq!(mul_split(x, y), (x as u128) * (y as u128));
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn proptest_mul_split(x in 0..1u64 << 63, y in 0..1u64 << 63) {
            proptest::prop_assert_eq!(mul_split(x, y), (x as u128) * (y as u128));
        }
    }
}
