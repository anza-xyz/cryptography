//! Four-way decomposition for BN254 subgroup scalars.
//!
//! Galbraith--Scott, Example 5: <https://eprint.iacr.org/2008/117.pdf>.
//! The basis spans an index-three sublattice of the Frobenius relation lattice.
//! Its exact first inverse row supplies fixed-point reciprocals; the rounding
//! below differs from nearest-integer Babai rounding and has its own bounds.
//! This module manipulates ordinary integers, never Montgomery residues.

use crate::backend::U256;

const X: i128 = 4_965_661_367_192_848_881;
const BASIS: [[i128; 4]; 4] = [
    [X + 1, X, X, -2 * X],
    [2 * X + 1, -X, -X - 1, -X],
    [2 * X, 2 * X + 1, 2 * X + 1, 2 * X + 1],
    [X - 1, 4 * X + 2, -2 * X + 1, X - 1],
];

// floor(2^256 * |n_i| / r), where the inverse first row is n_i/r.
const RECIPROCALS: [[u64; 4]; 4] = [
    [0xd0cb46fd51906254, 0xc444fab18d269b9d, 0, 0],
    [
        0x001378f5ee78976d,
        0x22df9f942d7d77c7,
        0x3d00631561b25729,
        1,
    ],
    [
        0x36510546a93478ab,
        0x916fcfca16bebbe4,
        0x9e80318ab0d92b94,
        0,
    ],
    [0xf7ae23ce89afae7c, 0xc444fab18d269b9a, 0, 0],
];

const COMPONENT_BOUNDS: [u128; 4] = [
    59_587_936_406_314_186_574,
    79_450_581_875_085_582_102,
    59_587_936_406_314_186_574,
    59_587_936_406_314_186_572,
];

const _: () = {
    let mut column = 0;
    while column < 4 {
        let mut bound = 0;
        let mut row = 0;
        while row < 4 {
            bound += 2 * BASIS[row][column].unsigned_abs();
            row += 1;
        }
        assert!(bound == COMPONENT_BOUNDS[column]);
        assert!(bound < 1u128 << 67);
        column += 1;
    }
};

// Exact schoolbook product for unrestricted limbs. In particular, these
// reciprocals do not satisfy the small limb-sum bound of the G05 Comba helper.
#[inline(always)]
fn product<const N: usize>(a: &U256, b: &[u64; N]) -> [u64; 8] {
    assert!(N <= 4);
    let mut out = [0; 8];
    for (i, &factor) in b.iter().enumerate() {
        let mut carry = 0;
        for (j, &word) in a.0.iter().enumerate() {
            let value = word as u128 * factor as u128 + out[i + j] as u128 + carry;
            out[i + j] = value as u64;
            carry = value >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

// Arithmetic modulo 2^256 intentionally discards the final carry/borrow.
// Only the final small result is interpreted as a signed integer.
#[inline(always)]
fn add(a: U256, b: U256) -> U256 {
    let mut result = [0; 4];
    let mut carry = 0;
    for (i, word) in result.iter_mut().enumerate() {
        let value = a.0[i] as u128 + b.0[i] as u128 + carry;
        *word = value as u64;
        carry = value >> 64;
    }
    U256::new(result)
}

#[inline(always)]
fn subtract(a: U256, b: U256) -> U256 {
    let mut result = [0; 4];
    let mut borrow = false;
    for (i, word) in result.iter_mut().enumerate() {
        let (difference, first) = a.0[i].overflowing_sub(b.0[i]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *word = difference;
        borrow = first || second;
    }
    U256::new(result)
}

/// Returns signed k_i with scalar = sum(k_i * p^i) (mod r), each |k_i|<2^67.
pub(super) fn decompose(scalar: &U256) -> [i128; 4] {
    // Let q_i=sign(n_i)*floor(s*floor(R*|n_i|/r)/R). For s<R, each
    // coefficient error |s*n_i/r-q_i| is <2. Since n*B=(r,0,0,0),
    // k=(s,0,0,0)-q*B has |k_j|<2*sum_i |B_ij|<2^67.
    let mut components = [*scalar, U256::zero(), U256::zero(), U256::zero()];
    for (i, reciprocal) in RECIPROCALS.iter().enumerate() {
        let wide = product(scalar, reciprocal);
        let quotient = U256::new([wide[4], wide[5], wide[6], wide[7]]);
        for (j, component) in components.iter_mut().enumerate() {
            let magnitude = BASIS[i][j].unsigned_abs();
            let wide = product(&quotient, &[magnitude as u64, (magnitude >> 64) as u64]);
            let term = U256::new([wide[0], wide[1], wide[2], wide[3]]);
            // Only the fourth inverse-row numerator is negative.
            *component = if (i == 3) ^ (BASIS[i][j] < 0) {
                add(*component, term)
            } else {
                subtract(*component, term)
            };
        }
    }
    core::array::from_fn(|i| {
        let negative = components[i].0[3] >> 63 != 0;
        let magnitude = if negative {
            subtract(U256::zero(), components[i])
        } else {
            components[i]
        };
        debug_assert_eq!(magnitude.0[2] | magnitude.0[3], 0);
        let magnitude = magnitude.0[0] as u128 | ((magnitude.0[1] as u128) << 64);
        debug_assert!(magnitude < COMPONENT_BOUNDS[i]);
        if negative {
            -(magnitude as i128)
        } else {
            magnitude as i128
        }
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ark_bn254::{Fq, Fr};
    use ark_ff::PrimeField;
    use num_bigint::{BigInt, BigUint};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn integer(words: &[u64]) -> BigUint {
        words
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |a, &b| (a << 64) + b)
    }

    fn numerators() -> [BigInt; 4] {
        let x = BigInt::from(X);
        [
            2u8 * &x * &x + 3u8 * &x + 1u8,
            12u8 * &x * &x * &x + 8u8 * &x * &x + &x,
            6u8 * &x * &x * &x + 4u8 * &x * &x + &x,
            -2i8 * &x * &x - &x,
        ]
    }

    #[test]
    fn basis_and_reciprocals_match_bn_parameters() {
        let r = BigInt::from(integer(&Fr::MODULUS.0));
        let p = BigInt::from(integer(&Fq::MODULUS.0));
        let lambda = &p % &r;
        let x = BigInt::from(X);
        assert_eq!(lambda, 6u8 * &x * &x);
        for row in BASIS {
            let mut power = BigInt::from(1);
            let mut value = BigInt::from(0);
            for word in row {
                value += word * &power;
                power = power * &lambda % &r;
            }
            assert_eq!(value % &r, BigInt::from(0));
        }
        let n = numerators();
        let radix = BigInt::from(1) << 256usize;
        for i in 0..4 {
            let value: BigInt = (0..4).map(|j| &n[j] * BASIS[j][i]).sum();
            assert_eq!(value, if i == 0 { r.clone() } else { BigInt::from(0) });
            let reciprocal = BigInt::from(integer(&RECIPROCALS[i]));
            assert_eq!(
                reciprocal,
                &radix * BigInt::from(n[i].magnitude().clone()) / &r
            );
        }
    }

    #[test]
    fn decomposition_matches_integer_oracle_at_quotient_boundaries() {
        let r = integer(&Fr::MODULUS.0);
        let lambda = integer(&Fq::MODULUS.0) % &r;
        let radix = BigUint::from(1u8) << 256usize;
        let n = numerators();
        let reciprocals: [BigUint; 4] = core::array::from_fn(|i| &radix * n[i].magnitude() / &r);
        let mut scalars = std::vec![
            BigUint::from(0u8),
            &r - 1u8,
            r.clone(),
            &r + 1u8,
            &radix - 1u8
        ];
        for bit in 0usize..256 {
            let power = BigUint::from(1u8) << bit;
            scalars.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        for reciprocal in &reciprocals {
            for multiple in 1..=64u64 {
                let threshold = (multiple * &radix + reciprocal - 1u8) / reciprocal;
                for value in [&threshold - 1u8, threshold.clone(), &threshold + 1u8] {
                    if value < radix {
                        scalars.push(value);
                    }
                }
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6773_5f73_706c_6974);
        scalars.extend((0..4096).map(|_| integer(&rng.random::<[u64; 4]>())));
        for scalar in scalars {
            let digits = scalar.to_u64_digits();
            let mut words = [0; 4];
            words[..digits.len()].copy_from_slice(&digits);
            let actual = decompose(&U256::new(words));
            let q: [BigInt; 4] = core::array::from_fn(|i| {
                BigInt::from_biguint(n[i].sign(), (&scalar * &reciprocals[i]) >> 256usize)
            });
            let mut recomposed = BigInt::from(0);
            let mut power = BigUint::from(1u8);
            for i in 0..4 {
                let expected = if i == 0 {
                    BigInt::from(scalar.clone())
                } else {
                    BigInt::from(0)
                } - (0..4).map(|j| &q[j] * BASIS[j][i]).sum::<BigInt>();
                assert_eq!(BigInt::from(actual[i]), expected);
                assert!(actual[i].unsigned_abs() < COMPONENT_BOUNDS[i]);
                recomposed += actual[i] * BigInt::from(power.clone());
                power = power * &lambda % &r;
            }
            let r_signed = BigInt::from(r.clone());
            let residue = ((recomposed % &r_signed) + &r_signed) % &r_signed;
            assert_eq!(residue, BigInt::from(scalar % &r));
        }
    }
}
