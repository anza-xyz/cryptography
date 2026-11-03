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
    for (limb, chunk) in a.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
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
