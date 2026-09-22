//! Bounded integer multiples of Montgomery Fq residues.
//!
//! Reduces bounded intermediates with 0<=value<10q. Public outputs stay
//! canonical with radix 2^256; a fifth limb retains the carry from 8*a.

use super::PortableBackend;
use crate::backend::{Field, Fq, MontgomeryBackend, U256};

const Q: [u64; 4] = Fq::MODULUS.0;

// With B=2^252, q=3B+d and 0 <= d < B/32. These inequalities include
// all possible lower limbs, not just an approximation to the high limb.
const _: () = {
    assert!(Q[3] >= 0x3000_0000_0000_0000);
    assert!(Q[3] < 0x3080_0000_0000_0000);
};

/// Reduces an integer `0 <= value < 10q`, returning a canonical residue.
#[inline(always)]
pub(crate) fn reduce(value: [u64; 5]) -> U256 {
    // k=floor(value/(3B)), obtained from the top five bits. Since value<10q,
    // k<=10. Writing value=3kB+s, 0<=s<3B, gives value-kq=s-kd in (-q,q).
    // Thus a negative result needs exactly one add-back; no subtraction follows.
    let estimate = ((value[4] << 4) | (value[3] >> 60)) / 3;
    debug_assert!(estimate <= 10);
    let mut result = [0; 4];
    let mut carry = 0i128;
    for (i, limb) in result.iter_mut().enumerate() {
        // -10W <= wide < W, hence the signed carry is in -10..=0.
        let wide = value[i] as i128 - estimate as i128 * Q[i] as i128 + carry;
        *limb = wide as u64;
        carry = wide >> 64;
    }
    let sign = value[4] as i128 + carry;
    debug_assert!((-1..=0).contains(&sign));
    if sign < 0 {
        let mut carry = 0u128;
        for (i, limb) in result.iter_mut().enumerate() {
            let wide = *limb as u128 + Q[i] as u128 + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
        // The low limbs represented 2^256 + remainder before this add-back.
        debug_assert_eq!(carry, 1);
    }
    U256::new(result)
}

impl PortableBackend<Fq> {
    /// Requires a canonical input. Returns N*a modulo q, for 1<=N<=8.
    #[inline]
    pub(crate) fn scale_small<const N: u64>(a: &U256) -> U256 {
        assert!(N > 0 && N <= 8);
        debug_assert!(Self::is_reduced(a));
        let mut wide = [0; 5];
        let mut carry = 0;
        for (i, limb) in wide[..4].iter_mut().enumerate() {
            let product = (a.0[i] as u128) * (N as u128) + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        wide[4] = carry as u64;
        // N*a<8q<10q, satisfying the shared reducer's exact range bound.
        reduce(wide)
    }
}

#[cfg(test)]
mod tests {
    fn check<const N: u64>(input: &BigUint, q: &BigUint) {
        let raw = input.to_u64_digits();
        let mut words = [0; 4];
        words[..raw.len()].copy_from_slice(&raw);
        let actual = PortableBackend::<Fq>::scale_small::<N>(&U256::new(words));
        assert_eq!(integer(&actual.0), (input * N) % q);
    }

    #[test]
    fn small_multiples_match_integer_oracle_at_reduction_and_carry_boundaries() {
        let q = integer(&Fq::MODULUS.0);
        let mut values = std::vec![BigUint::from(0u8), BigUint::from(1u8), &q - 1u8];
        for n in [3u64, 4, 8] {
            for multiple in 1..n {
                let boundary = (&q * multiple) / n;
                values.extend([&boundary - 1u8, boundary.clone(), &boundary + 1u8]);
            }
            // Scaling by eight can carry beyond 256 bits before reduction.
            let carry_boundary = (BigUint::from(1u8) << 256usize) / n;
            for value in [
                &carry_boundary - 1u8,
                carry_boundary.clone(),
                &carry_boundary + 1u8,
            ] {
                if value < q {
                    values.push(value);
                }
            }
        }
        let mut rng = StdRng::seed_from_u64(0x736d_616c_6c5f_6671);
        values.extend((0..4096).map(|_| integer(&rng.random::<[u64; 4]>()) % &q));
        for value in values {
            check::<3>(&value, &q);
            check::<4>(&value, &q);
            check::<8>(&value, &q);
        }
    }

    extern crate std;
    use super::*;
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn integer(words: &[u64]) -> BigUint {
        words
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |v, &w| (v << 64) + w)
    }
}
