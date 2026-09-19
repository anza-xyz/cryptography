//! GLV decomposition and joint signed recoding for BN254 G1 and G2.
//!
//! The lattice basis is (A, -B), (B, C), with C=A+B and AC+B^2=r.
//! For the eigenvalue paired with BETA_MONT, A-B*lambda and B+C*lambda
//! vanish modulo r. The conjugate G2 endomorphism has the same eigenvalue.
//! None of these integer operations use Montgomery form.

use crate::backend::U256;

// beta * 2^256 mod q. The paired eigenvalue is
// 21888242871839275217838484774961031246154997185409878258781734729429964517155.
pub(super) const BETA_MONT: U256 = U256::new([
    0x3350c88e13e80b9c,
    0x7dce557cdb5e56b9,
    0x6001b4b8b615564a,
    0x2682e617020217e0,
]);
const A: [u64; 2] = [0x8211bbeb7d4f1128, 0x6f4d8248eeb859fc];
const B: [u64; 1] = [0x89d3256894d213e3];
const C: [u64; 2] = [0x0be4e1541221250b, 0x6f4d8248eeb859fd];
// Downward-rounded fixed-point reciprocals, with R=2^256.
const G1: [u64; 3] = [0x5398fd0300ff6565, 0x4ccef014a773d2d2, 2]; // floor(R*C/r)
const G2: [u64; 2] = [0xd91d232ec7e0b3d7, 2]; // floor(R*B/r)

pub(super) struct SplitScalar {
    pub k1: u128,
    pub k2: u128,
    pub k2_negative: bool,
}

/// Signed joint digits, least significant first. A digit encodes d1+3*d2,
/// where each component is in {-1,0,1}; at most 129 positions are needed.
pub(super) struct JointDigits {
    digits: [i8; 129],
    len: usize,
}

impl JointDigits {
    pub(super) fn as_slice(&self) -> &[i8] {
        &self.digits[..self.len]
    }
}

impl SplitScalar {
    /// Simple joint sparse form, including the sign of the second component.
    /// See Grabner, Heuberger and Prodinger, Algorithm 1:
    /// https://www.math.aau.at/heuberger/publications/pdf/Joint_Sparse.pdf
    pub(super) fn joint_digits(&self) -> JointDigits {
        let (mut k1, mut k2) = (self.k1, self.k2);
        let mut result = JointDigits {
            digits: [0; 129],
            len: 0,
        };
        while k1 | k2 != 0 {
            let (mut d1, mut d2) = ((k1 & 1) as i8, (k2 & 1) as i8);
            if d1 == 1 && d2 == 1 {
                // Make both remaining magnitudes even at the next position.
                d1 = 2 - (k1 & 3) as i8;
                d2 = 2 - (k2 & 3) as i8;
            } else if d1 != d2 && (k1 ^ k2) & 2 != 0 {
                // Align the next parities when exactly one magnitude is odd.
                d1 = -d1;
                d2 = -d2;
            }
            result.digits[result.len] = d1 + 3 * if self.k2_negative { -d2 } else { d2 };
            result.len += 1;
            // (k-d)/2, shifting first to avoid k+1 overflowing at u128::MAX.
            // The result is at most 2^127; at most 129 steps consume any u128.
            k1 = (k1 >> 1) + u128::from(d1 < 0);
            k2 = (k2 >> 1) + u128::from(d2 < 0);
        }
        result
    }

    /// Prepares a signed schedule only when its estimated cost beats binary.
    /// The two callers retain weights 7/11 (G1) and 17/30 (G2), with 100 for
    /// table setup. These are latency heuristics, not execution-time bounds.
    pub(super) fn prepare<const DOUBLING: u32, const ADDITION: u32>(
        &self,
        scalar: &U256,
    ) -> Option<JointDigits> {
        debug_assert!(scalar.0[1] != 0 || scalar.0[2] != 0 || scalar.0[3] != 0);
        let bits = if scalar.0[3] != 0 {
            256 - scalar.0[3].leading_zeros()
        } else if scalar.0[2] != 0 {
            192 - scalar.0[2].leading_zeros()
        } else {
            128 - scalar.0[1].leading_zeros()
        };
        let ones: u32 = scalar.0.iter().map(|limb| limb.count_ones()).sum();
        let binary_cost = DOUBLING * (bits - 1) + ADDITION * (ones - 1);
        let joint = self.k1 | self.k2;
        // Signed digits cannot reduce the number of positions below the
        // magnitudes' bit length. Reject on this bound before recoding.
        if joint == 0 || DOUBLING * (127 - joint.leading_zeros()) + 100 >= binary_cost {
            return None;
        }
        let digits = self.joint_digits();
        let nonzero = digits
            .as_slice()
            .iter()
            .filter(|&&digit| digit != 0)
            .count() as u32;
        // Counts are at most 128; for the fixed weights both costs fit u32.
        let signed_cost = DOUBLING * (digits.len as u32 - 1) + ADDITION * (nonzero - 1) + 100;
        (signed_cost < binary_cost).then_some(digits)
    }
}

/// Full unsigned product, retaining every carry. N is at most four.
#[inline(always)]
fn mul_wide<const N: usize>(a: &U256, b: &[u64; N]) -> [u64; 8] {
    assert!(N <= 4);
    let mut out = [0u64; 8];
    for (i, factor) in b.iter().enumerate() {
        let mut carry = 0;
        for (j, limb) in a.0.iter().enumerate() {
            // For W=2^64, (W-1)^2 + (W-1) + (W-1) = W^2-1.
            let t = (*limb as u128) * (*factor as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        // Earlier rows have not written this limb.
        out[i + 4] = carry;
    }
    out
}

#[inline(always)]
fn low_u256(value: [u64; 8]) -> U256 {
    debug_assert!(value[4..].iter().all(|limb| *limb == 0));
    U256::new([value[0], value[1], value[2], value[3]])
}

#[inline(always)]
fn add_integer(a: &U256, b: &U256) -> U256 {
    let mut out = U256::zero();
    let mut carry = 0;
    for (i, limb) in out.0.iter_mut().enumerate() {
        let sum = (a.0[i] as u128) + (b.0[i] as u128) + carry;
        *limb = sum as u64;
        carry = sum >> 64;
    }
    debug_assert_eq!(carry, 0);
    out
}

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

#[inline(always)]
fn narrow(value: U256) -> u128 {
    debug_assert_eq!(value.0[2] | value.0[3], 0);
    (value.0[0] as u128) | ((value.0[1] as u128) << 64)
}

/// Returns k1 + signed(k2)*lambda = scalar (mod r), for all scalar < 2^256.
#[inline(always)]
pub(super) fn decompose(scalar: &U256) -> SplitScalar {
    let product = mul_wide(scalar, &G1);
    let b1 = U256::new([product[4], product[5], product[6], product[7]]);
    let product = mul_wide(scalar, &G2);
    let b2 = U256::new([product[4], product[5], product[6], product[7]]);

    // Put d1=scalar*C/r-b1 and d2=scalar*B/r-b2. Rounding both reciprocals
    // down and scalar<R imply 0<=d1,d2<2. Then k1=A*d1+B*d2 is in [0,2C),
    // and k2=-B*d1+C*d2 is in (-2B,2C). Since 2C<2^128, both magnitudes fit.
    // Also b1*A+b2*B<=scalar, so that sum fits 256 bits without a carry.
    let lattice_x = add_integer(&low_u256(mul_wide(&b1, &A)), &low_u256(mul_wide(&b2, &B)));
    let (k1, borrow) = sub_integer(scalar, &lattice_x);
    debug_assert!(!borrow);

    // b1<2^130, b2<2^66, B<2^64 and C<2^127: each product fits 256 bits.
    let positive = low_u256(mul_wide(&b1, &B));
    let negative = low_u256(mul_wide(&b2, &C));
    let (difference, k2_negative) = sub_integer(&positive, &negative);
    let magnitude = if k2_negative {
        sub_integer(&negative, &positive).0
    } else {
        difference
    };
    SplitScalar {
        k1: narrow(k1),
        k2: narrow(magnitude),
        k2_negative,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_bn254::{Fr, g1::Config};
    use ark_ec::scalar_mul::glv::GLVConfig;
    use ark_ff::PrimeField;
    use num_bigint::{BigInt, BigUint};
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

    #[test]
    fn joint_signed_digits_reconstruct_exact_components() {
        // Independently decode the signed table index and reconstruct with
        // arbitrary-precision integers, including the possible bit-128 carry.
        let pairs = [
            (-1i8, -1i8),
            (0, -1),
            (1, -1),
            (-1, 0),
            (0, 0),
            (1, 0),
            (-1, 1),
            (0, 1),
            (1, 1),
        ];
        let mut seen = [false; 9];
        let mut saw_carry = false;
        let mut check = |k1, k2| {
            for k2_negative in [false, true] {
                let split = SplitScalar {
                    k1,
                    k2,
                    k2_negative,
                };
                let recoding = split.joint_digits();
                let digits = recoding.as_slice();
                assert!(digits.len() <= 129);
                assert_eq!(digits.is_empty(), k1 == 0 && k2 == 0);
                if let Some(last) = digits.last() {
                    assert_ne!(*last, 0);
                }
                let (mut left, mut right) = (BigInt::from(0), BigInt::from(0));
                for &digit in digits.iter().rev() {
                    assert!((-4..=4).contains(&digit));
                    let index = (digit + 4) as usize;
                    seen[index] = true;
                    let (a, b) = pairs[index];
                    left = left * 2 + a;
                    right = right * 2 + b;
                }
                assert_eq!(left, BigInt::from(k1));
                assert_eq!(
                    right,
                    if k2_negative {
                        -BigInt::from(k2)
                    } else {
                        BigInt::from(k2)
                    }
                );
                for adjacent in digits.windows(2) {
                    let (a, b) = pairs[(adjacent[0] + 4) as usize];
                    let (next_a, next_b) = pairs[(adjacent[1] + 4) as usize];
                    if a.abs() != b.abs() {
                        assert_eq!(next_a.abs(), next_b.abs());
                    } else if a != 0 {
                        assert_eq!((next_a, next_b), (0, 0));
                    }
                }
                saw_carry |= digits.len() == 129;
            }
        };
        let mut boundaries = std::vec![0, 1, 2, 3, u128::MAX];
        for bit in 0..128 {
            let power = 1u128 << bit;
            boundaries.extend([power - 1, power, power + 1]);
        }
        for value in boundaries {
            for other in [0, 1, 2, 3, u64::MAX as u128, value, !value, u128::MAX] {
                check(value, other);
                check(other, value);
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6a73_665f_7061_6972);
        for _ in 0..4096 {
            check(rng.random(), rng.random());
        }
        assert!(seen.into_iter().all(|v| v));
        assert!(saw_carry);
    }

    #[test]
    fn parameters_and_reciprocal_bounds() {
        let (a, b, c) = (big(&A), big(&B), big(&C));
        let r = big(&Fr::MODULUS.0);
        let radix = BigUint::from(1u8) << 256usize;
        let lambda = BigInt::from(big(&Config::LAMBDA.into_bigint().0));
        assert_eq!(c, &a + &b);
        assert_eq!(&a * &c + &b * &b, r);
        assert!((&c << 1usize) < (BigUint::from(1u8) << 128usize));
        for (g, numerator) in [(big(&G1), &radix * &c), (big(&G2), &radix * &b)] {
            assert!(&g * &r <= numerator);
            assert!((&g + 1u8) * &r > numerator);
        }
        let (a, b, c, r) = (
            BigInt::from(a),
            BigInt::from(b),
            BigInt::from(c),
            BigInt::from(r),
        );
        assert_eq!((&a - &b * &lambda) % &r, BigInt::from(0));
        assert_eq!((&b + &c * &lambda) % &r, BigInt::from(0));
    }

    fn check_product<const N: usize>(a: U256, b: [u64; N]) {
        assert_eq!(big(&mul_wide(&a, &b)), big(&a.0) * big(&b));
    }

    #[test]
    fn wide_products_match_arbitrary_precision() {
        for a in [
            U256::zero(),
            U256::new([u64::MAX; 4]),
            U256::new([0, 0, 0, 1 << 63]),
        ] {
            check_product(a, [u64::MAX]);
            check_product(a, [u64::MAX; 2]);
            check_product(a, [u64::MAX; 3]);
            check_product(a, [u64::MAX; 4]);
        }
        let mut rng = StdRng::seed_from_u64(0x676c_765f_7769_6465);
        for _ in 0..4096 {
            let a = U256::new(rng.random());
            check_product(a, rng.random::<[u64; 1]>());
            check_product(a, rng.random::<[u64; 2]>());
            check_product(a, rng.random::<[u64; 3]>());
            check_product(a, rng.random::<[u64; 4]>());
        }
    }

    fn check_decomposition(scalar: U256) -> SplitScalar {
        let split = decompose(&scalar);
        let (a, b, c) = (big(&A), big(&B), big(&C));
        let r = big(&Fr::MODULUS.0);
        let radix = BigUint::from(1u8) << 256usize;
        let s = big(&scalar.0);
        // Derive the reciprocals independently, then retain every bit of the
        // integer products and signed subtractions in the oracle.
        let b1 = (&s * ((&radix * &c) / &r)) >> 256usize;
        let b2 = (&s * ((&radix * &b) / &r)) >> 256usize;
        let expected_k1 = BigInt::from(s.clone()) - BigInt::from(&b1 * &a + &b2 * &b);
        let expected_k2 = BigInt::from(&b1 * &b) - BigInt::from(&b2 * &c);
        let k1 = BigInt::from(split.k1);
        let k2 = if split.k2_negative {
            -BigInt::from(split.k2)
        } else {
            BigInt::from(split.k2)
        };
        assert_eq!(k1, expected_k1, "scalar={scalar:?}");
        assert_eq!(k2, expected_k2, "scalar={scalar:?}");
        assert!(BigUint::from(split.k1) < (&c << 1usize));
        assert!(BigUint::from(split.k2) < (&c << 1usize));
        if split.k2_negative {
            assert_ne!(split.k2, 0);
            assert!(BigUint::from(split.k2) < (&b << 1usize));
        }
        let lambda = BigInt::from(big(&Config::LAMBDA.into_bigint().0));
        assert_eq!(
            (k1 + lambda * k2 - BigInt::from(s)) % BigInt::from(r),
            BigInt::from(0)
        );
        split
    }

    #[test]
    fn seeded_decomposition_matches_arbitrary_precision() {
        let mut rng = StdRng::seed_from_u64(0x676c_765f_7370_6c74);
        for _ in 0..4096 {
            check_decomposition(U256::new(rng.random()));
        }
    }

    #[test]
    fn decomposition_at_integer_and_quotient_boundaries() {
        let one = BigUint::from(1u8);
        let radix = &one << 256usize;
        let r = big(&Fr::MODULUS.0);
        let mut scalars = Vec::new();
        let mut neighbors = |center: BigUint| {
            if center > BigUint::from(0u8) && (&center - &one) < radix {
                scalars.push(word(&(&center - &one)));
            }
            if center < radix {
                scalars.push(word(&center));
            }
            if (&center + &one) < radix {
                scalars.push(word(&(&center + &one)));
            }
        };
        for bit in 0..=256 {
            neighbors(&one << bit);
        }
        for multiple in 1..=5u8 {
            neighbors(&r * multiple);
        }
        // Negative second components occur close to these quotient changes
        // and are too rare to rely on uniformly random scalars finding them.
        for numerator in [big(&B), big(&C)] {
            let reciprocal = (&radix * numerator) / &r;
            for j in (1..=64u8)
                .map(BigUint::from)
                .chain((0..130).map(|bit| &one << bit))
            {
                neighbors((j * &radix + &reciprocal - &one) / &reciprocal);
            }
        }
        let (mut positive, mut negative, mut zero) = (false, false, false);
        for scalar in scalars {
            let split = check_decomposition(scalar);
            negative |= split.k2_negative;
            positive |= !split.k2_negative && split.k2 != 0;
            zero |= split.k1 == 0 && split.k2 == 0;
        }
        assert!(positive && negative && zero);
    }
}
