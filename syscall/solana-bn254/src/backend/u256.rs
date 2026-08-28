//! Core 256-bit integer representation.

/// A 256-bit unsigned integer represented as four 64-bit limbs.
///
/// Limbs are ordered little-endian: least significant at index 0,
/// most significant at index 3.
///
/// `#[repr(C)]` guarantees a sequential memory layout, allowing the
/// x86_64 inline assembly to safely access limbs via pointer offsets.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct U256(pub [u64; 4]);

impl U256 {
    /// Creates a new `U256` from a fixed-size array of limbs.
    #[inline(always)]
    pub const fn new(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Creates a `U256` initialized to zero.
    #[inline(always)]
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    /// Creates a `U256` initialized to one.
    #[inline(always)]
    pub const fn one() -> Self {
        Self([1, 0, 0, 0])
    }
}
