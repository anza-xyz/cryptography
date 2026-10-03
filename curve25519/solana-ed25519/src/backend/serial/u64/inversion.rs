//! Variable-time inversion modulo \\(p = 2^{255} - 19\\) using batches of 62
//! divsteps.
//!
//! The recurrence follows Bernstein--Yang, <https://eprint.iacr.org/2019/266>,
//! Sections 8--11, in the variable-time form described in libsecp256k1's
//! safegcd notes. Only the low words of `f` and `g` drive a batch of 62
//! steps; the signed full-width values and the modular coefficients are then
//! updated once per batch with the accumulated 2x2 matrix. Twelve batches
//! suffice for any 256-bit input (Theorem 11.2 gives at most 741 divsteps).
//!
//! This is several times faster than the Fermat inversion in `FieldElement`,
//! but its running time depends on the input, so it is only for public data:
//! point compression in the curve25519 syscalls, never anything secret.

use super::field::FieldElement51;

/// \\(p = 2^{255} - 19\\) as little-endian 64-bit limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// \\(-p^{-1} \bmod 2^{64}\\), so that `x + (x * P_INV mod 2^62) * p` is
/// divisible by \\(2^{62}\\).
const P_INV: u64 = 0x86bc_a1af_286b_ca1b;

const STEPS: u32 = 62;
const MASK: u64 = (1 << STEPS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Signed {
    limbs: [u64; 4],
    // Value = limbs + high*2^256. GCD states satisfy -p <= value <= p,
    // so high is either -1 or 0.
    high: i64,
}

#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let res = (a as u128) + (b as u128) + (carry as u128);
    (res as u64, (res >> 64) as u64)
}

#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (r1, b1) = a.overflowing_sub(b);
    let (r2, b2) = r1.overflowing_sub(borrow);
    (r2, (b1 as u64) | (b2 as u64))
}

/// Runs 62 divsteps on the low words of `f` and `g`, returning the new
/// `delta` and the transition matrix.
#[inline(always)]
fn divsteps(mut delta: i32, mut f: u64, mut g: u64) -> (i32, [[i64; 2]; 2]) {
    let (mut u, mut v, mut q, mut r) = (1i64, 0i64, 0i64, 1i64);
    let mut remaining = STEPS;
    while remaining != 0 {
        // Consecutive even-g divsteps leave f and the second matrix row
        // unchanged: combine their shifts and first-row scalings. Cap at the
        // batch boundary, including g = 0 (trailing_zeros returns 64).
        let zeros = g.trailing_zeros().min(remaining);
        if zeros != 0 {
            g >>= zeros;
            let scale = 1i64 << zeros;
            u *= scale;
            v *= scale;
            delta += zeros as i32;
            remaining -= zeros;
            if remaining == 0 {
                break;
            }
        }
        debug_assert_eq!(g & 1, 1);
        remaining -= 1;
        if delta > 0 {
            delta = 1 - delta;
            (f, g) = (g, g.wrapping_sub(f) >> 1);
            (u, v, q, r) = (2 * q, 2 * r, q - u, r - v);
        } else {
            delta += 1;
            g = g.wrapping_add(f) >> 1;
            q += u;
            r += v;
            u *= 2;
            v *= 2;
        }
    }
    // Each step at most doubles each row's absolute sum, so every
    // coefficient fits a signed 64-bit word.
    debug_assert!(u.unsigned_abs() + v.unsigned_abs() <= 1 << STEPS);
    debug_assert!(q.unsigned_abs() + r.unsigned_abs() <= 1 << STEPS);
    (delta, [[u, v], [q, r]])
}

/// Divides `limbs + high * 2^256` by `2^62`; the low 62 bits must be zero.
#[inline(always)]
fn shift(limbs: [u64; 4], high: i128) -> Signed {
    debug_assert_eq!(limbs[0] & MASK, 0);
    Signed {
        limbs: [
            (limbs[0] >> STEPS) | (limbs[1] << (64 - STEPS)),
            (limbs[1] >> STEPS) | (limbs[2] << (64 - STEPS)),
            (limbs[2] >> STEPS) | (limbs[3] << (64 - STEPS)),
            (limbs[3] >> STEPS) | ((high as u64) << (64 - STEPS)),
        ],
        high: (high >> STEPS) as i64,
    }
}

/// `(u * f + v * g) / 2^62`, exact for the matrices produced by `divsteps`.
#[inline(always)]
fn update_integer(f: Signed, g: Signed, [u, v]: [i64; 2]) -> Signed {
    let mut limbs = [0u64; 4];
    let mut carry = 0i128;
    for (i, word) in limbs.iter_mut().enumerate() {
        let sum = u as i128 * f.limbs[i] as i128 + v as i128 * g.limbs[i] as i128 + carry;
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

/// `(u * d + v * e) / 2^62 mod p`, returned in `[0, p)`.
#[inline(always)]
fn update_coefficient(d: [u64; 4], e: [u64; 4], [u, v]: [i64; 2]) -> [u64; 4] {
    let low = d[0]
        .wrapping_mul(u as u64)
        .wrapping_add(e[0].wrapping_mul(v as u64));
    let correction = low.wrapping_mul(P_INV) & MASK;
    let mut limbs = [0u64; 4];
    let mut carry = 0i128;
    // |u| + |v| <= 2^62 and correction < 2^62, so each limb's signed sum,
    // including the carry, stays strictly below 2^127 in magnitude.
    for (i, word) in limbs.iter_mut().enumerate() {
        let sum = u as i128 * d[i] as i128
            + v as i128 * e[i] as i128
            + correction as i128 * P[i] as i128
            + carry;
        *word = sum as u64;
        carry = sum >> 64;
    }
    let mut result = shift(limbs, carry);
    // d, e < p gives -2^62 p < u d + v e < 2^62 p. Adding correction * p and
    // dividing exactly by 2^62 leaves a value in (-p, 2p).
    debug_assert!((-1..=1).contains(&result.high));
    if result.high < 0 {
        let mut carry = 0;
        for (limb, &modulus) in result.limbs.iter_mut().zip(&P) {
            (*limb, carry) = adc(*limb, modulus, carry);
        }
        debug_assert_eq!(carry, 1);
        result.limbs
    } else {
        let mut reduced = [0u64; 4];
        let mut borrow = 0;
        for (i, word) in reduced.iter_mut().enumerate() {
            (*word, borrow) = sbb(result.limbs[i], P[i], borrow);
        }
        if result.high != 0 || borrow == 0 {
            debug_assert_eq!(result.high as u64, borrow);
            reduced
        } else {
            result.limbs
        }
    }
}

/// `p - x` for `0 < x < p`, and `0` for `x = 0`.
fn negate_mod_p(x: [u64; 4]) -> [u64; 4] {
    if x == [0; 4] {
        return x;
    }
    let mut out = [0u64; 4];
    let mut borrow = 0;
    for (i, word) in out.iter_mut().enumerate() {
        (*word, borrow) = sbb(P[i], x[i], borrow);
    }
    debug_assert_eq!(borrow, 0);
    out
}

/// Returns `a^-1`, or zero for zero, in variable time.
pub(crate) fn invert_vartime(a: &FieldElement51) -> FieldElement51 {
    let bytes = a.to_bytes();
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    if limbs == [0; 4] {
        return FieldElement51::ZERO;
    }

    let mut f = Signed { limbs: P, high: 0 };
    let mut g = Signed { limbs, high: 0 };
    let (mut d, mut e) = ([0u64; 4], [1u64, 0, 0, 0]);
    let mut delta = 1;
    // Invariants: a * d = f and a * e = g (mod p). Each batch maps (f, g)
    // and (d, e) by the same matrix and divides both by 2^62, exactly for
    // the integers and modulo p for the coefficients, which preserves them.
    while g.high != 0 || g.limbs != [0; 4] {
        let (next_delta, matrix) = divsteps(delta, f.limbs[0], g.limbs[0]);
        delta = next_delta;
        (f, g) = (
            update_integer(f, g, matrix[0]),
            update_integer(f, g, matrix[1]),
        );
        (d, e) = (
            update_coefficient(d, e, matrix[0]),
            update_coefficient(d, e, matrix[1]),
        );
    }
    // At termination f = +/-gcd(p, a) = +/-1, so d = +/-a^-1; the sign of f
    // corrects d.
    let result = if f.high < 0 {
        debug_assert_eq!(f.limbs, [u64::MAX; 4]);
        negate_mod_p(d)
    } else {
        debug_assert_eq!(f.limbs, [1, 0, 0, 0]);
        d
    };

    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(result) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    FieldElement51::from_bytes(&out)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn modulus_constants_are_consistent() {
        assert_eq!(P_INV.wrapping_mul(P[0]), u64::MAX);
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(P) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        // p encodes as 2^255 - 19, whose canonical residue is zero.
        assert_eq!(FieldElement51::from_bytes(&bytes).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn vartime_inverse_matches_fermat() {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut inputs = std::vec![
            FieldElement51::ZERO,
            FieldElement51::ONE,
            FieldElement51::MINUS_ONE,
            -&FieldElement51([2, 0, 0, 0, 0]),
            FieldElement51([19, 0, 0, 0, 0]),
        ];
        for bit in 0..255u32 {
            let mut bytes = [0u8; 32];
            bytes[(bit / 8) as usize] = 1 << (bit % 8);
            let power = FieldElement51::from_bytes(&bytes);
            inputs.push(power);
            inputs.push(&power - &FieldElement51::ONE);
            inputs.push(-&power);
        }
        // Non-canonical limb representations, as produced by field arithmetic.
        inputs.push(FieldElement51([(1 << 54) - 1; 5]));
        inputs.push(FieldElement51([(1 << 51) + 5, 7, 0, 0, 1 << 52]));
        for _ in 0..4096 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            inputs.push(FieldElement51::from_bytes(&bytes));
        }
        for x in inputs {
            let expected = crate::field::FieldElement::invert(&x);
            let actual = invert_vartime(&x);
            assert_eq!(actual.to_bytes(), expected.to_bytes(), "x = {x:?}");
            if x.to_bytes() != [0u8; 32] {
                assert_eq!((&actual * &x).to_bytes(), FieldElement51::ONE.to_bytes());
            }
        }
    }
}
