//! Constant-time Legendre symbol modulo \\(p = 2^{255} - 19\\).
//!
//! This is a port of the `legendre()` routine of Thomas Pornin's
//! [crrl](https://github.com/pornin/crrl) (`src/backend/w64/gf255_m64.rs`),
//! used under the MIT license; see ACKNOWLEDGEMENTS.md. The algorithm is the
//! optimized binary GCD of <https://eprint.iacr.org/2020/972>, run without
//! the Bézout coefficients and with a running sign updated by quadratic
//! reciprocity. Fifteen batches of 31 steps on 64-bit approximations and a
//! 43-step tail cover any 255-bit input; the GCD itself was mechanically
//! verified by Mahboubi, Melquiond, Strub and Vallejos Parada (ITP 2026).
//!
//! Every step runs for every input, so the running time does not depend on
//! the value.

use super::field::FieldElement51;

/// \\(p = 2^{255} - 19\\) as little-endian 64-bit limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// The sign bit of `x` as a signed 64-bit integer, expanded to 64 bits.
#[inline(always)]
const fn sgnw(x: u64) -> u64 {
    ((x as i64) >> 63) as u64
}

/// `x - y - borrow`, and the outgoing borrow.
#[inline(always)]
const fn subborrow_u64(x: u64, y: u64, borrow: u8) -> (u64, u8) {
    let z = (x as u128)
        .wrapping_sub(y as u128)
        .wrapping_sub(borrow as u128);
    (z as u64, (z >> 127) as u8)
}

/// `x1*y1 + x2*y2` over 128 bits, as `(lo, hi)`.
#[inline(always)]
const fn umull_x2(x1: u64, y1: u64, x2: u64, y2: u64) -> (u64, u64) {
    let z = (x1 as u128) * (y1 as u128) + (x2 as u128) * (y2 as u128);
    (z as u64, (z >> 64) as u64)
}

/// `x1*y1 + x2*y2 + z3` over 128 bits, as `(lo, hi)`.
#[inline(always)]
const fn umull_x2_add(x1: u64, y1: u64, x2: u64, y2: u64, z3: u64) -> (u64, u64) {
    let z = (x1 as u128) * (y1 as u128) + (x2 as u128) * (y2 as u128) + (z3 as u128);
    (z as u64, (z >> 64) as u64)
}

/// `|a*f + b*g| / 2^31` for `|f|, |g| <= 2^31` and `a, b < 2^255`, and a
/// mask that is all ones if `a*f + b*g` was negative.
#[inline]
fn lindiv31abs(a: &[u64; 4], b: &[u64; 4], f: u64, g: u64) -> ([u64; 4], u64) {
    // Replace f and g with abs(f) and abs(g), but remember the
    // original signs.
    let sf = sgnw(f);
    let f = (f ^ sf).wrapping_sub(sf);
    let sg = sgnw(g);
    let g = (g ^ sg).wrapping_sub(sg);

    // Apply the signs of f and g to the source operands.
    let (a0, cc) = subborrow_u64(a[0] ^ sf, sf, 0);
    let (a1, cc) = subborrow_u64(a[1] ^ sf, sf, cc);
    let (a2, cc) = subborrow_u64(a[2] ^ sf, sf, cc);
    let (a3, _) = subborrow_u64(a[3] ^ sf, sf, cc);
    let (b0, cc) = subborrow_u64(b[0] ^ sg, sg, 0);
    let (b1, cc) = subborrow_u64(b[1] ^ sg, sg, cc);
    let (b2, cc) = subborrow_u64(b[2] ^ sg, sg, cc);
    let (b3, _) = subborrow_u64(b[3] ^ sg, sg, cc);

    // Compute a*f+b*g into d0:d1:d2:d3:t. Since f and g are at
    // most 2^31, we can add two 128-bit products with no overflow.
    let (d0, t) = umull_x2(a0, f, b0, g);
    let (d1, t) = umull_x2_add(a1, f, b1, g, t);
    let (d2, t) = umull_x2_add(a2, f, b2, g, t);
    let (d3, t) = umull_x2_add(a3, f, b3, g, t);

    // If a < 0, then the result is overestimated by f*2^256;
    // similarly, if b < 0 then the result is overestimated by g*2^256.
    // We must thus subtract 2^256*(sa*f+sb*g), with sa and sb being
    // the signs of a and b, respectively (1 for negative, 0 otherwise).
    let t = t.wrapping_sub(f & sgnw(a3));
    let t = t.wrapping_sub(g & sgnw(b3));

    // Shift-right the value by 31 bits.
    let d0 = (d0 >> 31) | (d1 << 33);
    let d1 = (d1 >> 31) | (d2 << 33);
    let d2 = (d2 >> 31) | (d3 << 33);
    let d3 = (d3 >> 31) | (t << 33);

    // If the result is negative, then negate it.
    let t = (t >> 63).wrapping_neg();
    let (d0, cc) = subborrow_u64(d0 ^ t, t, 0);
    let (d1, cc) = subborrow_u64(d1 ^ t, t, cc);
    let (d2, cc) = subborrow_u64(d2 ^ t, t, cc);
    let (d3, _) = subborrow_u64(d3 ^ t, t, cc);

    ([d0, d1, d2, d3], t)
}

/// The Legendre symbol of `x` in constant time: `1` for a nonzero square,
/// `-1` for a nonsquare and `0` for zero.
pub(crate) fn legendre(x: &FieldElement51) -> i64 {
    // The GCD runs on the canonical value in [0, p); `to_bytes` reduces fully.
    let bytes = x.to_bytes();
    let a_canonical = [
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
    ];
    let is_zero_mask = {
        let m = a_canonical[0] | a_canonical[1] | a_canonical[2] | a_canonical[3];
        // m | -m has its top bit set exactly when m is nonzero.
        !sgnw(m | m.wrapping_neg())
    };

    // The algorithm is very similar to the optimized binary GCD for
    // modular inversion, with the following differences:
    //  - We do not keep track of the 'u' and 'v' values.
    //  - In each inner iteration, the running symbol value is
    //    adjusted, taking into account the low 2 or 3 bits of the
    //    involved values.
    //  - Since we need a couple of bits of look-ahead, we can only
    //    run 29 iterations in the inner loop, and we need an extra
    //    recomputation step for the next 2.
    // Otherwise, the 'a' and 'b' values are modified exactly as in
    // the binary GCD, so that we get the same guaranteed convergence
    // in a total of 508 iterations.
    let mut a = a_canonical;
    let mut b = P;
    let mut ls = 0u64; // running symbol information in the low bit

    // Outer loop
    for _ in 0..15 {
        // Get approximations of a and b over 64 bits.
        let m3 = a[3] | b[3];
        let m2 = a[2] | b[2];
        let m1 = a[1] | b[1];
        let tnz3 = sgnw(m3 | m3.wrapping_neg());
        let tnz2 = sgnw(m2 | m2.wrapping_neg()) & !tnz3;
        let tnz1 = sgnw(m1 | m1.wrapping_neg()) & !tnz3 & !tnz2;
        let tnzm = (m3 & tnz3) | (m2 & tnz2) | (m1 & tnz1);
        let tnza = (a[3] & tnz3) | (a[2] & tnz2) | (a[1] & tnz1);
        let tnzb = (b[3] & tnz3) | (b[2] & tnz2) | (b[1] & tnz1);
        let snza = (a[2] & tnz3) | (a[1] & tnz2) | (a[0] & tnz1);
        let snzb = (b[2] & tnz3) | (b[1] & tnz2) | (b[0] & tnz1);

        let s = tnzm.leading_zeros();
        let sm = (31_i32.wrapping_sub(s as i32) >> 31) as u64;
        let tnza = tnza ^ (sm & (tnza ^ ((tnza << 32) | (snza >> 32))));
        let tnzb = tnzb ^ (sm & (tnzb ^ ((tnzb << 32) | (snzb >> 32))));
        let s = s - (32 & (sm as u32));
        let tnza = tnza << s;
        let tnzb = tnzb << s;

        let tzx = !(tnz1 | tnz2 | tnz3);
        let tnza = tnza | (a[0] & tzx);
        let tnzb = tnzb | (b[0] & tzx);
        let mut xa = (a[0] & 0x7fff_ffff) | (tnza & 0xffff_ffff_8000_0000);
        let mut xb = (b[0] & 0x7fff_ffff) | (tnzb & 0xffff_ffff_8000_0000);

        // First 29 inner iterations.
        let mut fg0 = 1u64;
        let mut fg1 = 1u64 << 32;
        for _ in 0..29 {
            let a_odd = (xa & 1).wrapping_neg();
            let (_, cc) = subborrow_u64(xa, xb, 0);
            let swap = a_odd & (cc as u64).wrapping_neg();
            ls ^= swap & ((xa & xb) >> 1);
            let t1 = swap & (xa ^ xb);
            xa ^= t1;
            xb ^= t1;
            let t2 = swap & (fg0 ^ fg1);
            fg0 ^= t2;
            fg1 ^= t2;
            xa = xa.wrapping_sub(a_odd & xb);
            fg0 = fg0.wrapping_sub(a_odd & fg1);
            xa >>= 1;
            fg1 <<= 1;
            ls ^= xb.wrapping_add(2) >> 2;
        }

        // Compute the updated a and b (low words only) to get enough
        // bits for the next two iterations.
        let fg0z = fg0.wrapping_add(0x7fff_ffff_7fff_ffff);
        let fg1z = fg1.wrapping_add(0x7fff_ffff_7fff_ffff);
        let f0 = (fg0z & 0xffff_ffff).wrapping_sub(0x7fff_ffff);
        let g0 = (fg0z >> 32).wrapping_sub(0x7fff_ffff);
        let f1 = (fg1z & 0xffff_ffff).wrapping_sub(0x7fff_ffff);
        let g1 = (fg1z >> 32).wrapping_sub(0x7fff_ffff);
        let mut a0 = a[0].wrapping_mul(f0).wrapping_add(b[0].wrapping_mul(g0)) >> 29;
        let mut b0 = a[0].wrapping_mul(f1).wrapping_add(b[0].wrapping_mul(g1)) >> 29;
        for _ in 0..2 {
            let a_odd = (xa & 1).wrapping_neg();
            let (_, cc) = subborrow_u64(xa, xb, 0);
            let swap = a_odd & (cc as u64).wrapping_neg();
            ls ^= swap & ((a0 & b0) >> 1);
            let t1 = swap & (xa ^ xb);
            xa ^= t1;
            xb ^= t1;
            let t2 = swap & (fg0 ^ fg1);
            fg0 ^= t2;
            fg1 ^= t2;
            let t3 = swap & (a0 ^ b0);
            a0 ^= t3;
            b0 ^= t3;
            xa = xa.wrapping_sub(a_odd & xb);
            fg0 = fg0.wrapping_sub(a_odd & fg1);
            a0 = a0.wrapping_sub(a_odd & b0);
            xa >>= 1;
            fg1 <<= 1;
            a0 >>= 1;
            ls ^= b0.wrapping_add(2) >> 2;
        }

        // Propagate updates to a and b.
        fg0 = fg0.wrapping_add(0x7fff_ffff_7fff_ffff);
        fg1 = fg1.wrapping_add(0x7fff_ffff_7fff_ffff);
        let f0 = (fg0 & 0xffff_ffff).wrapping_sub(0x7fff_ffff);
        let g0 = (fg0 >> 32).wrapping_sub(0x7fff_ffff);
        let f1 = (fg1 & 0xffff_ffff).wrapping_sub(0x7fff_ffff);
        let g1 = (fg1 >> 32).wrapping_sub(0x7fff_ffff);

        let (na, nega) = lindiv31abs(&a, &b, f0, g0);
        let (nb, _) = lindiv31abs(&a, &b, f1, g1);
        ls ^= nega & (nb[0] >> 1);
        a = na;
        b = nb;
    }

    // Final iterations: values are at most 45 bits now. We do not
    // need to keep track of update coefficients. Just like the GCD,
    // we need only 43 iterations, because after 43 iterations,
    // value a is 0 or 1, and b is 1, and no further modification to
    // the Legendre symbol may happen.
    let mut xa = a[0];
    let mut xb = b[0];
    for _ in 0..43 {
        let a_odd = (xa & 1).wrapping_neg();
        let (_, cc) = subborrow_u64(xa, xb, 0);
        let swap = a_odd & (cc as u64).wrapping_neg();
        ls ^= swap & ((xa & xb) >> 1);
        let t1 = swap & (xa ^ xb);
        xa ^= t1;
        xb ^= t1;
        xa = xa.wrapping_sub(a_odd & xb);
        xa >>= 1;
        ls ^= xb.wrapping_add(2) >> 2;
    }

    // At this point, if the source value was not zero, then the low
    // bit of ls contains the QR status (0 = square, 1 = non-square),
    // which we need to convert to the expected value (+1 or -1).
    // If x == 0, then we return 0, per the API.
    let r = 1i64.wrapping_sub(((ls & 1) << 1) as i64);
    r & !(is_zero_mask as i64)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn legendre_matches_known_residues() {
        // p = 5 mod 8, so 2 is a nonsquare and -1 is a square.
        assert_eq!(legendre(&FieldElement51::ZERO), 0);
        assert_eq!(legendre(&FieldElement51::ONE), 1);
        assert_eq!(legendre(&FieldElement51::MINUS_ONE), 1);
        let two = &FieldElement51::ONE + &FieldElement51::ONE;
        assert_eq!(legendre(&two), -1);
        let four = &two + &two;
        assert_eq!(legendre(&four), 1);
        // Non-canonical encodings of zero and one.
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        assert_eq!(legendre(&FieldElement51::from_bytes(&bytes)), 0);
        bytes[0] = 0xee;
        assert_eq!(legendre(&FieldElement51::from_bytes(&bytes)), 1);
        // 2^255 - 1 = 18 mod p, and 18 = 2 * 9 is a nonsquare.
        assert_eq!(legendre(&FieldElement51::from_bytes(&[0xff; 32])), -1);
        // Non-canonical limb representation, as produced by field arithmetic.
        let two_p = FieldElement51([
            (1 << 52) - 38,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 52) - 2,
        ]);
        assert_eq!(legendre(&two_p), 0);
        // p - 2^103 is a nonsquare: (-1|p) = 1 and (2|p)^103 = -1.
        let mut bytes = [0u8; 32];
        bytes[12] = 0x80;
        assert_eq!(legendre(&-&FieldElement51::from_bytes(&bytes)), -1);
    }
}
