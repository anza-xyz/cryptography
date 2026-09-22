//! Variable-time width-w signed recoding of ordinary unsigned integers.
//!
//! A width-w NAF uses odd digits of absolute value below 2^(w-1), with at
//! least w-1 zero positions after each nonzero digit. No group-order reduction
//! occurs here. See the related table/recoding use in Arkworks:
//! https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/scalar_mul/wnaf.rs

use crate::backend::U256;

pub(super) struct Digits<const L: usize> {
    pub digits: [i8; L],
    pub len: usize,
}

fn recode<const W: u32, const N: usize, const L: usize>(mut scalar: [u64; N]) -> Digits<L> {
    assert!((3..=5).contains(&W));
    assert!(N > 0 && N <= 4 && L > 64 * N);
    let mut result = Digits {
        digits: [0; L],
        len: 0,
    };
    while scalar.iter().any(|&word| word != 0) {
        let digit = if scalar[0] & 1 == 0 {
            0
        } else {
            let low = (scalar[0] & ((1 << W) - 1)) as i16;
            (if low >= 1 << (W - 1) {
                low - (1 << W)
            } else {
                low
            }) as i8
        };
        result.digits[result.len] = digit;
        result.len += 1;
        // Shift first: (k-d)/2 = (k>>1)-floor(d/2). In particular, a
        // negative digit at U256::MAX must not first compute overflowing k-d.
        for i in 0..N {
            scalar[i] = (scalar[i] >> 1) | if i + 1 < N { scalar[i + 1] << 63 } else { 0 };
        }
        let half = digit >> 1;
        if half < 0 {
            let mut carry = (-half) as u64;
            for word in &mut scalar {
                let (sum, overflow) = word.overflowing_add(carry);
                *word = sum;
                carry = u64::from(overflow);
            }
            debug_assert_eq!(carry, 0);
        } else if half > 0 {
            let mut borrow = half as u64;
            for word in &mut scalar {
                let (difference, underflow) = word.overflowing_sub(borrow);
                *word = difference;
                borrow = u64::from(underflow);
            }
            debug_assert_eq!(borrow, 0);
        }
    }
    result
}

pub(super) fn from_u128<const W: u32>(value: u128) -> Digits<129> {
    recode::<W, 2, 129>([value as u64, (value >> 64) as u64])
}

pub(super) fn from_u256<const W: u32>(value: &U256) -> Digits<257> {
    recode::<W, 4, 257>(value.0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use num_bigint::{BigInt, BigUint};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn integer(limbs: &[u64]) -> BigUint {
        limbs
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |v, &w| (v << 64) + w)
    }

    fn verify<const W: u32, const L: usize>(digits: Digits<L>, expected: BigUint) {
        let actual = digits.digits[..digits.len]
            .iter()
            .rev()
            .fold(BigInt::from(0), |v, &digit| (v << 1) + digit);
        assert_eq!(actual, BigInt::from(expected));
        assert!(digits.len == 0 || digits.digits[digits.len - 1] != 0);
        let mut previous = None;
        for (i, &digit) in digits.digits[..digits.len].iter().enumerate() {
            if digit == 0 {
                continue;
            }
            assert_eq!(digit.unsigned_abs() & 1, 1);
            assert!(u32::from(digit.unsigned_abs()) < 1 << (W - 1));
            if let Some(last) = previous {
                assert!(i - last >= W as usize);
            }
            previous = Some(i);
        }
    }

    fn check<const W: u32>(value: U256) {
        verify::<W, 257>(from_u256::<W>(&value), integer(&value.0));
        let low = (value.0[0] as u128) | ((value.0[1] as u128) << 64);
        verify::<W, 129>(from_u128::<W>(low), integer(&value.0[..2]));
    }

    #[test]
    fn widths_reconstruct_boundary_and_seeded_unsigned_integers() {
        let radix = BigUint::from(1u8) << 256usize;
        let mut values = std::vec![BigUint::from(0u8), &radix - 1u8];
        for bit in 0usize..256 {
            let power = BigUint::from(1u8) << bit;
            values.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        let mut rng = StdRng::seed_from_u64(0x776e_6166_5f62_6974);
        values.extend((0..4096).map(|_| integer(&rng.random::<[u64; 4]>())));
        for value in values {
            let raw = value.to_u64_digits();
            let mut limbs = [0; 4];
            limbs[..raw.len()].copy_from_slice(&raw);
            let value = U256::new(limbs);
            check::<3>(value);
            check::<4>(value);
            check::<5>(value);
        }
    }
}
