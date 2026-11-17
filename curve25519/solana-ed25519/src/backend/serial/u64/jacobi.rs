//! Variable-time Jacobi symbol modulo \\(p = 2^{255} - 19\\), for public data:
//! Stein's binary GCD, as in Algorithm 1 of <https://eprint.iacr.org/2020/972>
//! without the inversion coefficients, tracking the sign of the symbol.

use super::field::FieldElement51;

/// \\(p = 2^{255} - 19\\) as little-endian 64-bit limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// `a - b` on the low `N` words, and whether it borrows.
#[inline(always)]
fn sub<const N: usize>(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut r = [0u64; 4];
    let mut borrow = false;
    for i in 0..N {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (x, b2) = x.overflowing_sub(borrow as u64);
        r[i] = x;
        borrow = b1 | b2;
    }
    (r, borrow)
}

/// `a >> s` on the low `N` words, for `0 < s < 64`.
#[inline(always)]
fn shr<const N: usize>(a: &mut [u64; 4], s: u32) {
    // Left shifts first: without BMI2 the shift count in cl then changes once.
    let mut carry = [0u64; 4];
    for i in 1..N {
        carry[i - 1] = a[i] << (64 - s);
    }
    for i in 0..N {
        a[i] = (a[i] >> s) | carry[i];
    }
}

/// Shifts the trailing zeros out of nonzero `a`, and returns how many.
#[inline(always)]
fn shift_out_zeros<const N: usize>(a: &mut [u64; 4]) -> u32 {
    let mut z = 0;
    while a[0] == 0 {
        *a = [a[1], a[2], a[3], 0];
        z += 64;
    }
    let s = a[0].trailing_zeros();
    if s > 0 {
        shr::<N>(a, s);
    }
    z + s
}

/// One iteration on odd `a` and `b` below \\(2^{64 N}\\). Returns the sign flip
/// in bit 0.
#[inline(always)]
fn step<const N: usize>(a: &mut [u64; 4], b: &mut [u64; 4]) -> u64 {
    // Select by the borrow rather than branch on the unpredictable a < b.
    let (d, borrow) = sub::<N>(a, b);
    let (e, _) = sub::<N>(b, a);
    let swap = (borrow as u64).wrapping_neg();
    // Reciprocity: -1 when both are 3 mod 4.
    let flip = swap & ((a[0] & b[0]) >> 1);
    for i in 0..N {
        b[i] ^= swap & (a[i] ^ b[i]);
        a[i] = d[i] ^ (swap & (d[i] ^ e[i]));
    }
    // b - a = -(a - b) has the same trailing zeros as a - b. a = b only at
    // a = b = 1, which ends the loops on more than one word.
    let mut z = d[0].trailing_zeros();
    if z < 64 {
        shr::<N>(a, z);
    } else if N > 1 {
        z = shift_out_zeros::<N>(a);
    }
    // (2 | b) = -1 when b is 3 or 5 mod 8, applied z times.
    flip ^ ((z & 1) as u64 & ((b[0] >> 1) ^ (b[0] >> 2)))
}

/// Iterations on the low `N` words while `a` or `b` needs all of them.
#[inline(always)]
fn run<const N: usize>(a: &mut [u64; 4], b: &mut [u64; 4], flips: &mut u64) {
    // a reaches zero only once b = 1, so on more than one word the top words
    // decide.
    while if N > 1 {
        (a[N - 1] | b[N - 1]) != 0
    } else {
        a[0] != 0
    } {
        *flips ^= step::<N>(a, b);
    }
}

/// Whether `x` is a square modulo \\(p\\), zero included.
pub(crate) fn is_square_vartime(x: &FieldElement51) -> bool {
    let bytes = x.to_bytes();
    let mut a = [0u64; 4];
    for (limb, chunk) in a.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    if a == [0; 4] {
        return true;
    }
    let mut b = P;
    // Bit 0 is the parity of the sign flips; (2 | p) = -1.
    let mut flips = (shift_out_zeros::<4>(&mut a) & 1) as u64;
    run::<4>(&mut a, &mut b, &mut flips);
    run::<3>(&mut a, &mut b, &mut flips);
    run::<2>(&mut a, &mut b, &mut flips);
    run::<1>(&mut a, &mut b, &mut flips);
    flips & 1 == 0
}

#[cfg(test)]
mod test {
    use super::*;
    use std::vec::Vec;

    /// The Legendre symbol: 0 for zero, 1 for a square, -1 for a nonsquare.
    fn symbol(x: &FieldElement51) -> i64 {
        if x.to_bytes() == [0u8; 32] {
            0
        } else if is_square_vartime(x) {
            1
        } else {
            -1
        }
    }

    /// Euler's criterion x^((p - 1) / 2) by square-and-multiply, independent
    /// of the GCD and of the `pow_p58` chain.
    fn euler_symbol(x: &FieldElement51) -> i64 {
        const EXPONENT: [u64; 4] = [
            0xffff_ffff_ffff_fff6,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x3fff_ffff_ffff_ffff,
        ];
        let mut acc = FieldElement51::ONE;
        for bit in (0..255).rev() {
            acc = acc.square();
            if (EXPONENT[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = &acc * x;
            }
        }
        let bytes = acc.to_bytes();
        if bytes == [0u8; 32] {
            0
        } else if bytes == FieldElement51::ONE.to_bytes() {
            1
        } else {
            assert_eq!(bytes, FieldElement51::MINUS_ONE.to_bytes());
            -1
        }
    }

    /// A field element from little-endian words, ignoring bit 255.
    fn fe(words: [u64; 4]) -> FieldElement51 {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        FieldElement51::from_bytes(&bytes)
    }

    fn words_shr(mut w: [u64; 4], n: u32) -> [u64; 4] {
        for _ in 0..n {
            let mut carry = 0;
            for limb in w.iter_mut().rev() {
                let next = *limb & 1;
                *limb = (*limb >> 1) | (carry << 63);
                carry = next;
            }
        }
        w
    }

    fn words_shl(mut w: [u64; 4], n: u32) -> [u64; 4] {
        for _ in 0..n {
            let mut carry = 0;
            for limb in w.iter_mut() {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
        }
        w
    }

    fn pow2(j: u32) -> [u64; 4] {
        words_shl([1, 0, 0, 0], j)
    }

    fn structured_inputs(rng: &mut impl rand::Rng) -> Vec<FieldElement51> {
        let one = FieldElement51::ONE;
        let mut inputs: Vec<FieldElement51> = Vec::new();
        // Small values and values just below p.
        for k in 0u64..=1024 {
            inputs.push(fe([k, 0, 0, 0]));
            inputs.push(-&fe([k, 0, 0, 0]));
        }
        // Around 2^j, 3 * 2^j, p - 2^j and p >> j.
        let nineteen = fe([19, 0, 0, 0]);
        for j in 0..255 {
            let pw = fe(pow2(j));
            let three_pw = &(&pw + &pw) + &pw;
            let p_shr = fe(words_shr(P, j));
            for base in [&pw, &three_pw, &-&pw, &p_shr, &-&p_shr] {
                let mut below = *base;
                let mut above = *base;
                inputs.push(*base);
                for _ in 0..3 {
                    below = &below - &one;
                    above = &above + &one;
                    inputs.push(below);
                    inputs.push(above);
                }
            }
            // 2^j +- 19; j = 254 is the 255-iteration input.
            inputs.push(&pw + &nineteen);
            inputs.push(&pw - &nineteen);
            inputs.push(-&(&pw + &nineteen));
            inputs.push(-&(&pw - &nineteen));
        }
        // r and p - r for random r of every bit length.
        for bits in 1..=255u32 {
            for _ in 0..2 {
                let mut r = [
                    rng.next_u64(),
                    rng.next_u64(),
                    rng.next_u64(),
                    rng.next_u64(),
                ];
                r = words_shr(words_shl(r, 256 - bits), 256 - bits);
                r[(bits as usize - 1) / 64] |= 1 << ((bits - 1) % 64);
                inputs.push(fe(r));
                inputs.push(-&fe(r));
            }
        }
        // Two-bit families 2^j +- 2^i and p - 2^j -+ 2^i.
        for j in 1..255u32 {
            let hi = fe(pow2(j));
            for i in [0, 1, j / 2, j - 1] {
                let lo = fe(pow2(i));
                inputs.push(&hi - &lo);
                inputs.push(&hi + &lo);
                inputs.push(-&(&hi + &lo));
                inputs.push(-&(&hi - &lo));
            }
        }
        // Bit patterns, in every word, at every shift.
        const PATTERNS: [u64; 20] = [
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x3333_3333_3333_3333,
            0xcccc_cccc_cccc_cccc,
            0x0f0f_0f0f_0f0f_0f0f,
            0xf0f0_f0f0_f0f0_f0f0,
            0x00ff_00ff_00ff_00ff,
            0xff00_ff00_ff00_ff00,
            0x0000_ffff_0000_ffff,
            0xffff_0000_ffff_0000,
            0x0000_0000_ffff_ffff,
            0xffff_ffff_0000_0000,
            0x8000_0000_0000_0001,
            0x7fff_ffff_ffff_ffff,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0xffff_ffff_ffff_ffff,
            0x9249_2492_4924_9249,
            0x8421_8421_8421_8421,
            0xdead_beef_cafe_babe,
        ];
        for w in PATTERNS {
            let mut values = std::vec![[w; 4]];
            for limb in 0..4 {
                for other in [0, u64::MAX] {
                    let mut words = [other; 4];
                    words[limb] = w;
                    values.push(words);
                }
            }
            for (n, v) in values.into_iter().enumerate() {
                inputs.push(fe(v));
                inputs.push(-&fe(v));
                let shifts: Vec<u32> = if n == 0 {
                    (1..255).collect()
                } else {
                    std::vec![1, 31, 32, 33, 63, 64, 65, 127, 128, 191, 192, 223, 224, 254]
                };
                for j in shifts {
                    inputs.push(fe(words_shr(v, j)));
                    inputs.push(-&fe(words_shr(v, j)));
                }
            }
        }
        // Sparse values with up to 8 set bits.
        for _ in 0..2000 {
            let mut words = [0u64; 4];
            for _ in 0..(2 + rng.next_u64() % 7) {
                let bit = (rng.next_u64() % 255) as usize;
                words[bit / 64] |= 1 << (bit % 64);
            }
            inputs.push(fe(words));
            inputs.push(-&fe(words));
        }
        // Fibonacci numbers mod p and their negations.
        let (mut f0, mut f1) = (FieldElement51::ZERO, FieldElement51::ONE);
        for _ in 0..400 {
            inputs.push(f1);
            inputs.push(-&f1);
            // Addition does not reduce the limbs.
            let f2 = FieldElement51::from_bytes(&(&f0 + &f1).to_bytes());
            f0 = f1;
            f1 = f2;
        }
        inputs
    }

    #[test]
    fn jacobi_matches_euler() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x7374_7275_6374_7572);
        let mut inputs = structured_inputs(&mut rng);
        for _ in 0..100_000 {
            inputs.push(fe([
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
            ]));
        }
        let mut seen = [0usize; 3];
        for x in &inputs {
            let s = symbol(x);
            assert_eq!(s, euler_symbol(x), "x = {x:?}");
            seen[(s + 1) as usize] += 1;
        }
        assert!(
            seen[0] > 50_000 && seen[1] > 0 && seen[2] > 50_000,
            "{seen:?}"
        );
    }
}
