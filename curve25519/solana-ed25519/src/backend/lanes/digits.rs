// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.

//! Digit schedules for the radix-16 rounds of the lane verifier.

use crate::scalar::Scalar;

/// Radix-16 positions a 129-bit scalar can occupy.
pub(crate) const HEEA_DIGITS: usize = 33;

/// Radix-16 positions in each half of tau s.
pub(crate) const JOINT_DIGITS: usize = 32;

/// Bit where the high half of tau s starts.
const JOINT_SPLIT: usize = 128;

/// Bits per radix-16 digit.
const WINDOW: usize = 4;

/// Signed radix-16 digits of a scalar below 2^129, truncated to the HEEA window
pub(crate) fn signed_digits(scalar: &Scalar) -> [i8; HEEA_DIGITS] {
    let full = scalar.as_radix_16();
    debug_assert!(full[HEEA_DIGITS..].iter().all(|&d| d == 0));
    let mut out = [0i8; HEEA_DIGITS];
    out.copy_from_slice(&full[..HEEA_DIGITS]);
    out
}

/// Negate a schedule digit by digit, which keeps every digit in -8..=8.
pub(crate) fn negate(digits: &mut [i8; HEEA_DIGITS]) {
    for d in digits.iter_mut() {
        *d = -*d;
    }
}

/// Radix-16 digits of tau s as joint table indices, low half in the low four bits
pub(crate) fn joint_digits(bytes: &[u8; 32]) -> [u8; JOINT_DIGITS] {
    let nibble = |bit: usize| (bytes[bit / 8] >> (bit % 8)) & 15;
    let mut out = [0u8; JOINT_DIGITS];
    for (i, digit) in out.iter_mut().enumerate() {
        *digit = nibble(WINDOW * i) | nibble(JOINT_SPLIT + WINDOW * i) << WINDOW;
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    // both halves come back from the joint digits
    #[test]
    fn joint_halves() {
        let mut state = 0x1234_5678_9abc_def1u64;
        for _ in 0..20_000u32 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&xorshift(&mut state).to_le_bytes());
            }
            bytes[31] &= 0x1f;
            let digits = joint_digits(&bytes);
            let mut lo: u128 = 0;
            let mut hi: u128 = 0;
            for &d in digits.iter().rev() {
                lo = lo << 4 | (d & 15) as u128;
                hi = hi << 4 | (d >> 4) as u128;
            }
            let mut half = [0u8; 16];
            half.copy_from_slice(&bytes[..16]);
            assert_eq!(lo, u128::from_le_bytes(half));
            half.copy_from_slice(&bytes[16..]);
            assert_eq!(hi, u128::from_le_bytes(half));
        }
    }
}
