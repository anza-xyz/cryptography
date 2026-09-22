//! Ordinary integer scalar normalization shared by the two curve groups.
//! Callers must establish subgroup membership before using the congruence.

use crate::backend::{Field, Fr, U256};

#[inline(always)]
fn sub_integer(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = U256::zero();
    let mut borrow = false;
    for (i, limb) in out.0.iter_mut().enumerate() {
        let (diff, first) = a.0[i].overflowing_sub(b.0[i]);
        let (diff, second) = diff.overflowing_sub(borrow as u64);
        *limb = diff;
        borrow = first || second;
    }
    (out, borrow)
}

/// Returns a magnitude at most floor(r/2) and its sign, congruent to scalar mod r.
/// These are ordinary integers, not Montgomery residues. Since 5r < 2^256 < 6r,
/// at most five subtractions reduce any U256 input. The complement r-reduced
/// then fits U256, and choosing the smaller magnitude gives a value below 2^253.
#[inline(always)]
pub(crate) fn center_scalar(scalar: &U256) -> (U256, bool) {
    let mut reduced = *scalar;
    for _ in 0..5 {
        let (next, borrow) = sub_integer(&reduced, &Fr::MODULUS);
        if borrow {
            break;
        }
        reduced = next;
    }
    let (complement, borrow) = sub_integer(&Fr::MODULUS, &reduced);
    debug_assert!(!borrow);
    if reduced
        .0
        .iter()
        .rev()
        .cmp(complement.0.iter().rev())
        .is_gt()
    {
        (complement, true)
    } else {
        (reduced, false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::vec::Vec;

    fn big(limbs: &[u64]) -> BigUint {
        BigUint::from_bytes_le(
            &limbs
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }

    fn word(value: &BigUint) -> U256 {
        assert!(value.bits() <= 256);
        let mut limbs = [0; 4];
        let digits = value.to_u64_digits();
        limbs[..digits.len()].copy_from_slice(&digits);
        U256::new(limbs)
    }

    fn check_centered_scalar(scalar: U256) {
        let r = big(&Fr::MODULUS.0);
        let reduced = big(&scalar.0) % &r;
        let expected_negative = reduced > (&r >> 1usize);
        let expected_magnitude = if expected_negative {
            &r - reduced
        } else {
            reduced
        };
        let (magnitude, negative) = center_scalar(&scalar);
        assert_eq!(negative, expected_negative, "scalar={scalar:?}");
        assert_eq!(big(&magnitude.0), expected_magnitude, "scalar={scalar:?}");
        assert!(big(&magnitude.0) <= (&r >> 1usize));
        if magnitude == U256::zero() {
            assert!(!negative);
        }
    }

    #[test]
    fn centered_scalars_match_arbitrary_precision() {
        let one = BigUint::from(1u8);
        let radix = &one << 256usize;
        let r = big(&Fr::MODULUS.0);
        assert!(&r * 5u8 < radix && radix < &r * 6u8);
        assert!((&r >> 1usize) < (&one << 253usize));
        check_centered_scalar(U256::zero());
        check_centered_scalar(U256::new([u64::MAX; 4]));
        let neighbors = |center: BigUint| {
            if center > BigUint::from(0u8) && (&center - &one) < radix {
                check_centered_scalar(word(&(&center - &one)));
            }
            if center < radix {
                check_centered_scalar(word(&center));
            }
            if (&center + &one) < radix {
                check_centered_scalar(word(&(&center + &one)));
            }
        };
        for bit in 0..=256 {
            neighbors(&one << bit);
        }
        for multiple in 0..=5u8 {
            neighbors(&r * multiple);
            neighbors(&r * multiple + (&r >> 1usize));
        }
        let mut rng = StdRng::seed_from_u64(0x676c_765f_6365_6e74);
        for _ in 0..4096 {
            check_centered_scalar(U256::new(rng.random()));
        }
    }
}
