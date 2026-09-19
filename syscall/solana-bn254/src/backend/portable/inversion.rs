//! Variable-time Montgomery inversion using batches of 62 divsteps.
//!
//! The recurrence follows Bernstein--Yang, https://eprint.iacr.org/2019/266,
//! Sections 8--11. Only low words drive a batch; signed full-width values and
//! canonical modular coefficients are updated once per batch.

use super::{Field, MontgomeryBackend, PortableBackend, U256, adc, sbb};

const STEPS: u32 = 62;
const MASK: u64 = (1 << STEPS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Signed {
    limbs: U256,
    // Value = limbs + high*2^256. GCD states satisfy -p <= value <= p,
    // so high is either -1 or 0, including for full-width prime moduli.
    high: i64,
}

#[inline(always)]
fn divsteps(mut delta: i32, mut f: u64, mut g: u64) -> (i32, [[i64; 2]; 2]) {
    let (mut u, mut v, mut q, mut r) = (1i64, 0i64, 0i64, 1i64);
    for _ in 0..STEPS {
        if delta > 0 && g & 1 != 0 {
            delta = 1 - delta;
            (f, g) = (g, g.wrapping_sub(f) >> 1);
            (u, v, q, r) = (2 * q, 2 * r, q - u, r - v);
        } else {
            delta += 1;
            if g & 1 != 0 {
                g = g.wrapping_add(f);
                q += u;
                r += v;
            }
            g >>= 1;
            u *= 2;
            v *= 2;
        }
    }
    // Each step increases each row's absolute sum by at most a factor of two.
    // Thus all coefficients and intermediate updates fit signed 64-bit words.
    debug_assert!(u.unsigned_abs() + v.unsigned_abs() <= 1 << STEPS);
    debug_assert!(q.unsigned_abs() + r.unsigned_abs() <= 1 << STEPS);
    (delta, [[u, v], [q, r]])
}

#[inline(always)]
fn shift(limbs: U256, high: i128) -> Signed {
    debug_assert_eq!(limbs.0[0] & MASK, 0);
    Signed {
        limbs: U256::new([
            (limbs.0[0] >> STEPS) | (limbs.0[1] << (64 - STEPS)),
            (limbs.0[1] >> STEPS) | (limbs.0[2] << (64 - STEPS)),
            (limbs.0[2] >> STEPS) | (limbs.0[3] << (64 - STEPS)),
            (limbs.0[3] >> STEPS) | ((high as u64) << (64 - STEPS)),
        ]),
        high: (high >> STEPS) as i64,
    }
}

#[inline(always)]
fn update_integer(f: Signed, g: Signed, [u, v]: [i64; 2]) -> Signed {
    let mut limbs = U256::zero();
    let mut carry = 0i128;
    for (i, word) in limbs.0.iter_mut().enumerate() {
        let sum = u as i128 * f.limbs.0[i] as i128 + v as i128 * g.limbs.0[i] as i128 + carry;
        *word = sum as u64;
        carry = sum >> 64;
    }
    let result = shift(
        limbs,
        carry + u as i128 * f.high as i128 + v as i128 * g.high as i128,
    );
    debug_assert!((-1..=0).contains(&result.high));
    result
}

#[inline(always)]
fn update_coefficient<F: Field>(d: U256, e: U256, [u, v]: [i64; 2]) -> U256 {
    let low = d.0[0]
        .wrapping_mul(u as u64)
        .wrapping_add(e.0[0].wrapping_mul(v as u64));
    let correction = low.wrapping_mul(F::INV) & MASK;
    let mut limbs = U256::zero();
    let mut carry = 0i128;
    // |u|+|v| <= 2^62, correction < 2^62. With W=2^64, the
    // per-limb absolute sum including carry is at most (2^63-1)*W,
    // strictly below 2^127. The signed carry fits i64 as well.
    for (i, word) in limbs.0.iter_mut().enumerate() {
        let sum = u as i128 * d.0[i] as i128
            + v as i128 * e.0[i] as i128
            + correction as i128 * F::MODULUS.0[i] as i128
            + carry;
        *word = sum as u64;
        carry = sum >> 64;
    }
    let mut result = shift(limbs, carry);
    // d,e < p implies -2^62*p < u*d+v*e < 2^62*p.
    // Adding correction*p and dividing exactly by 2^62 gives (-p,2p).
    debug_assert!((-1..=1).contains(&result.high));
    if result.high < 0 {
        let mut carry = 0;
        for i in 0..4 {
            (result.limbs.0[i], carry) = adc(result.limbs.0[i], F::MODULUS.0[i], carry);
        }
        debug_assert_eq!(carry, 1);
        result.limbs
    } else {
        let mut reduced = U256::zero();
        let mut borrow = 0;
        for (i, word) in reduced.0.iter_mut().enumerate() {
            (*word, borrow) = sbb(result.limbs.0[i], F::MODULUS.0[i], borrow);
        }
        if result.high != 0 || borrow == 0 {
            debug_assert_eq!(result.high as u64, borrow);
            reduced
        } else {
            result.limbs
        }
    }
}

#[inline]
pub(super) fn invert<F: Field>(a: &U256) -> Option<U256> {
    if *a == U256::zero() {
        return None;
    }
    let mut f = Signed {
        limbs: F::MODULUS,
        high: 0,
    };
    let mut g = Signed { limbs: *a, high: 0 };
    let (mut d, mut e) = (U256::zero(), F::R2);
    let mut delta = 1;
    // a*d = f*R^2 and a*e = g*R^2 (mod p). The matrix/2^62
    // updates preserve both invariants. Every field coefficient is canonical.
    while g.high != 0 || g.limbs != U256::zero() {
        let (next_delta, matrix) = divsteps(delta, f.limbs.0[0], g.limbs.0[0]);
        delta = next_delta;
        (f, g) = (
            update_integer(f, g, matrix[0]),
            update_integer(f, g, matrix[1]),
        );
        (d, e) = (
            update_coefficient::<F>(d, e, matrix[0]),
            update_coefficient::<F>(d, e, matrix[1]),
        );
    }
    // Theorem 11.2 gives at most 741 divsteps for 256-bit inputs,
    // or twelve complete batches. Thus |delta| <= 745 fits i32.
    // At termination f = +/-gcd(p,a) = +/-1. Its sign corrects d.
    if f.high < 0 {
        debug_assert_eq!(f.limbs, U256::new([u64::MAX; 4]));
        Some(PortableBackend::<F>::neg(&d))
    } else {
        debug_assert_eq!(f.limbs, U256::one());
        Some(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Fq, Fr};
    use ark_ff::MontConfig;
    use num_bigint::{BigInt, Sign};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[derive(MontConfig)]
    #[modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663"]
    #[generator = "3"]
    struct FullWidthConfig;
    struct FullWidth;
    impl Field for FullWidth {
        const MODULUS: U256 = U256::new(<FullWidthConfig as MontConfig<4>>::MODULUS.0);
        const INV: u64 = <FullWidthConfig as MontConfig<4>>::INV;
        const R2: U256 = U256::new(<FullWidthConfig as MontConfig<4>>::R2.0);
    }

    fn integer(value: U256) -> BigInt {
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(value.0) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        BigInt::from_bytes_le(Sign::Plus, &bytes)
    }

    fn signed(value: Signed) -> BigInt {
        integer(value.limbs) + (BigInt::from(value.high) << 256)
    }

    #[test]
    fn batches_match_full_integer_divsteps() {
        let mut rng = StdRng::seed_from_u64(0x6469_7673_7465_7073);
        for _ in 0..256 {
            let mut f = Signed {
                limbs: FullWidth::MODULUS,
                high: 0,
            };
            let mut g = Signed {
                limbs: U256::new(rng.random()),
                high: 0,
            };
            let mut delta = 1;
            let (mut big_f, mut big_g) = (signed(f), signed(g));
            let mut reference_delta = delta;
            for _ in 0..12 {
                let (next_delta, matrix) = divsteps(delta, f.limbs.0[0], g.limbs.0[0]);
                for _ in 0..STEPS {
                    let odd = &big_g & BigInt::from(1u8) != BigInt::from(0u8);
                    if reference_delta > 0 && odd {
                        reference_delta = 1 - reference_delta;
                        (big_f, big_g) = (big_g.clone(), (&big_g - &big_f) >> 1);
                    } else {
                        reference_delta += 1;
                        if odd {
                            big_g += &big_f;
                        }
                        big_g >>= 1;
                    }
                }
                delta = next_delta;
                (f, g) = (
                    update_integer(f, g, matrix[0]),
                    update_integer(f, g, matrix[1]),
                );
                assert_eq!(delta, reference_delta);
                assert_eq!(signed(f), big_f);
                assert_eq!(signed(g), big_g);
                for [u, v] in matrix {
                    assert!(u.unsigned_abs() + v.unsigned_abs() <= 1 << STEPS);
                }
            }
            assert_eq!(big_g, BigInt::from(0u8));
        }
    }

    fn coefficients_match_fermat<F: Field>() {
        let p = integer(F::MODULUS);
        let divisor = BigInt::from(1u8) << STEPS;
        let inverse = divisor.modpow(&(&p - 2u8), &p);
        let mut rng = StdRng::seed_from_u64(0x636f_6566_6669_6369);
        let mut pm1 = F::MODULUS;
        pm1.0[0] -= 1; // The modulus is odd.
        let values = [U256::zero(), U256::one(), pm1, F::R2];
        let bound = 1i64 << STEPS;
        let rows = [
            [bound, 0],
            [-bound, 0],
            [0, -bound],
            [bound / 2, bound / 2],
            [-bound / 2, -bound / 2],
            [bound - 1, -1],
            [1, 1 - bound],
        ];
        let check = |d, e, [u, v]: [i64; 2]| {
            let numerator = integer(d) * u + integer(e) * v;
            let expected = ((numerator * &inverse) % &p + &p) % &p;
            let actual = integer(update_coefficient::<F>(d, e, [u, v]));
            assert_eq!(actual, expected);
            assert!(actual < p);
        };
        for d in values {
            for e in values {
                for row in rows {
                    check(d, e, row);
                }
            }
        }
        for _ in 0..256 {
            let mut sample = || loop {
                let value = U256::new(rng.random());
                if PortableBackend::<F>::is_reduced(&value) {
                    break value;
                }
            };
            let d = sample();
            let e = sample();
            let (_, matrix) = divsteps(1, F::MODULUS.0[0], rng.random());
            for row in matrix {
                check(d, e, row);
            }
        }
    }

    #[test]
    fn canonical_coefficient_updates_match_fermat() {
        coefficients_match_fermat::<Fq>();
        coefficients_match_fermat::<Fr>();
        coefficients_match_fermat::<FullWidth>();
    }
}
