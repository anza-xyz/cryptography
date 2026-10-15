//! Shared Montgomery reduction for wide Fq intermediates.

use super::{adc, mac, sbb};
use crate::backend::{Field, Fq, U256};

/// Returns `input * R^-1 mod q` as a canonical Fq residue, where `R = 2^256`.
///
/// Requires `0 <= input < qR`. Classical REDC adds `Mq` with `M < R`, so its
/// quotient is below `2q < R` and a single conditional subtraction suffices.
#[inline]
pub(super) fn reduce(input: [u64; 8]) -> U256 {
    let mut t = [0; 9];
    t[..8].copy_from_slice(&input);
    for i in 0..4 {
        let m = t[i].wrapping_mul(Fq::INV);
        let mut carry = 0;
        for j in 0..4 {
            (t[i + j], carry) = mac(t[i + j], m, Fq::MODULUS.0[j], carry);
        }
        for limb in &mut t[i + 4..] {
            (*limb, carry) = adc(*limb, 0, carry);
        }
        debug_assert_eq!(carry, 0);
    }
    debug_assert_eq!(t[8], 0);
    let mut d = [0; 4];
    let mut borrow = 0;
    for i in 0..4 {
        (d[i], borrow) = sbb(t[i + 4], Fq::MODULUS.0[i], borrow);
    }
    let mask = 0u64.wrapping_sub(borrow);
    U256::new(core::array::from_fn(|i| (t[i + 4] & mask) | (d[i] & !mask)))
}
