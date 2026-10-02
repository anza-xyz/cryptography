//! Variable-time Jacobi symbol modulo \\(p = 2^{255} - 19\\).
//!
//! A port of libsecp256k1's `secp256k1_jacobi64_maybe_var` (Peter Dettman,
//! Pieter Wuille; MIT licence, see ACKNOWLEDGEMENTS.md) to this modulus.
//! It runs batches of 62 "posdivsteps", a variant of the Bernstein--Yang
//! divsteps that keeps both values positive so that the Jacobi symbol can be
//! tracked from their low bits alone: dividing `g` by two flips the symbol
//! when `f = ±3 (mod 8)`, swapping `f` and `g` flips it when both are
//! `3 (mod 4)`, and adding a multiple of `f` to `g` leaves it unchanged.
//!
//! Unlike divsteps, posdivsteps have no proven iteration bound. Random
//! inputs need 11 to 15 batches, but small values converge slowly (up to
//! about 60 batches for values below 2^16), so two reductions run first:
//! since `p = 1 (mod 4)`, the symbol of `x` equals that of `p - x` and the
//! smaller of the two is used; and a value below 2^64 is handled by one
//! Euclidean step, `(x | p) = ±(p mod x | x)`, followed by a 64-bit binary
//! Jacobi computation. Of the remaining inputs, random ones converge within
//! 15 batches and the slowest structured ones found (`2^k - 1` and
//! `p - 2^k`) within 26; the computation gives up after 28 and reports
//! `None`, and callers then fall back to an exponentiation, so the worst
//! case stays bounded. When it does return, the result is exact.

use super::field::FieldElement51;

/// Number of 62-bit limbs holding a value below \\(2^{256}\\).
const LIMBS: usize = 5;
const M62: u64 = u64::MAX >> 2;

/// \\(p\\) in signed 62-bit limbs.
const MODULUS: [i64; LIMBS] = [
    0x3fff_ffff_ffff_ffed,
    0x3fff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
    0x7f,
];

const BATCHES: usize = 28;

/// `-f^{-1} mod 64` for odd `f`, indexed by `(f >> 1) & 31`.
const NEG_INV64: [u8; 32] = {
    let mut table = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let f = (2 * i + 1) as u8;
        // Newton iteration from the exact inverse modulo 8 (f^-1 = f).
        let mut inv = f;
        inv = inv.wrapping_mul(2u8.wrapping_sub(f.wrapping_mul(inv)));
        inv = inv.wrapping_mul(2u8.wrapping_sub(f.wrapping_mul(inv)));
        table[i] = inv.wrapping_neg() & 63;
        i += 1;
    }
    table
};

struct Transition {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 62 posdivsteps on the low 64 bits of `f` and `g` (which must both be the
/// values modulo \\(2^{64}\\), since the symbol tracking needs `f mod 8`).
/// Flips bit 0 of `jac` whenever the symbol `(g | f)` changes sign; the
/// other bits of `jac` are meaningless. Returns the new `eta` (`-delta`).
#[inline(always)]
fn posdivsteps(mut eta: i64, f0: u64, g0: u64, jac: &mut u64) -> (i64, Transition) {
    let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
    let (mut f, mut g) = (f0, g0);
    let mut i = 62u32;

    loop {
        // A sentinel bit counts zeros only up to i. Those divsteps all just
        // halve g; an odd number of halvings flips the symbol if f = 3 or 5
        // (mod 8), which is bit 1 xor bit 2 of f.
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= i64::from(zeros);
        i -= zeros;
        *jac ^= u64::from(zeros) & ((f >> 1) ^ (f >> 2));
        if i == 0 {
            break;
        }
        debug_assert_eq!(f & 1, 1);
        debug_assert_eq!(g & 1, 1);

        // Keep each cancellation width constant at its call site.
        #[inline(always)]
        fn cancellation(eta: i64, i: u32, f: u64, g: u64, mask: u64) -> (u64, u64) {
            let limit = (eta + 1).min(i64::from(i));
            debug_assert!(limit > 0 && limit <= 62);
            let m = (u64::MAX >> (64 - limit)) & mask;
            let w = g.wrapping_mul(u64::from(NEG_INV64[((f >> 1) & 31) as usize])) & m;
            (m, w)
        }
        let (m, w) = if eta < 0 {
            // Negate eta and swap f and g. Swapping flips the symbol when
            // both are 3 (mod 4).
            eta = -eta;
            core::mem::swap(&mut f, &mut g);
            core::mem::swap(&mut u, &mut q);
            core::mem::swap(&mut v, &mut r);
            *jac ^= (f & g) >> 1;
            // Cancel up to 6 low bits of g at once, but no more than eta+1,
            // after which eta would change sign again, and no more than i.
            cancellation(eta, i, f, g, 63)
        } else {
            // Here eta tends to be small, so cancelling up to 4 bits suffices.
            cancellation(eta, i, f, g, 15)
        };
        // g += w*f leaves (g | f) unchanged.
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
        debug_assert_eq!(g & m, 0);
    }

    (
        eta,
        Transition {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// Replaces `(f, g)` by `t * (f, g) / 2^62` over the first `len` limbs; the
/// division is exact for a posdivsteps transition.
#[inline(always)]
fn update_fg(len: usize, f: &mut [i64; LIMBS], g: &mut [i64; LIMBS], t: &Transition) {
    let (u, v, q, r) = (
        i128::from(t.u),
        i128::from(t.v),
        i128::from(t.q),
        i128::from(t.r),
    );
    let mut cf = u * i128::from(f[0]) + v * i128::from(g[0]);
    let mut cg = q * i128::from(f[0]) + r * i128::from(g[0]);
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..len {
        cf += u * i128::from(f[i]) + v * i128::from(g[i]);
        cg += q * i128::from(f[i]) + r * i128::from(g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[len - 1] = cf as i64;
    g[len - 1] = cg as i64;
}

/// `p` as little-endian 64-bit words.
const P_WORDS: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// Classical binary Jacobi symbol `(a | n)` for odd `n`, both below 2^64.
fn jacobi_u64(mut a: u64, mut n: u64) -> i8 {
    debug_assert_eq!(n & 1, 1);
    let mut negative = false;
    a %= n;
    while a != 0 {
        let zeros = a.trailing_zeros();
        a >>= zeros;
        // (2 | n) = -1 iff n = 3 or 5 (mod 8).
        if zeros & 1 == 1 && matches!(n & 7, 3 | 5) {
            negative = !negative;
        }
        // Reciprocity for odd coprime a, n.
        if a & 3 == 3 && n & 3 == 3 {
            negative = !negative;
        }
        core::mem::swap(&mut a, &mut n);
        a %= n;
    }
    if n != 1 {
        0
    } else if negative {
        -1
    } else {
        1
    }
}

/// `(x | p)` for `0 < x < 2^64` by one Euclidean step: strip factors of two
/// (each flips the symbol, as `p = 5 (mod 8)`), then `(x | p) = (p | x)`
/// since `p = 1 (mod 4)`, and `(p | x) = (p mod x | x)`.
fn jacobi_small(x: u64) -> i8 {
    debug_assert!(x != 0);
    let zeros = x.trailing_zeros();
    let odd = x >> zeros;
    let mut remainder = 0u64;
    for &word in P_WORDS.iter().rev() {
        remainder = ((((remainder as u128) << 64) | u128::from(word)) % u128::from(odd)) as u64;
    }
    let symbol = jacobi_u64(remainder, odd);
    if zeros & 1 == 1 { -symbol } else { symbol }
}

/// Splits little-endian 64-bit words into five 62-bit limbs.
fn limbs_from_words(words: &[u64; 4]) -> [i64; LIMBS] {
    [
        (words[0] & M62) as i64,
        (((words[0] >> 62) | (words[1] << 2)) & M62) as i64,
        (((words[1] >> 60) | (words[2] << 4)) & M62) as i64,
        (((words[2] >> 58) | (words[3] << 6)) & M62) as i64,
        (words[3] >> 56) as i64,
    ]
}

/// The Jacobi (here Legendre) symbol of `x` modulo \\(p\\): `Some(1)` for a
/// nonzero square, `Some(-1)` for a non-square, `Some(0)` for zero, and
/// `None` if the iteration did not converge (so the caller must use another
/// method). Variable time; for public data only.
pub(crate) fn jacobi_vartime(x: &FieldElement51) -> Option<i8> {
    jacobi_with_cap(x, BATCHES).map(|(symbol, _)| symbol)
}

/// `jacobi_vartime` with an explicit batch cap, also returning the number
/// of batches used.
fn jacobi_with_cap(x: &FieldElement51, cap: usize) -> Option<(i8, usize)> {
    let bytes = x.to_bytes();
    if bytes == [0u8; 32] {
        return Some((0, 0));
    }

    let mut words = [0u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    // (x | p) = (p - x | p): use the smaller representative.
    if words[3] >> 62 != 0 {
        let mut borrow = 0u64;
        for (word, &modulus) in words.iter_mut().zip(&P_WORDS) {
            let (diff, b1) = modulus.overflowing_sub(*word);
            let (diff, b2) = diff.overflowing_sub(borrow);
            *word = diff;
            borrow = u64::from(b1 | b2);
        }
        debug_assert_eq!(borrow, 0);
    }
    // Small values converge slowly in posdivsteps; one Euclidean step
    // reduces them to a 64-bit problem.
    if words[1] | words[2] | words[3] == 0 {
        return Some((jacobi_small(words[0]), 0));
    }

    // Start with f = p, g = x, eta = -delta = -1.
    let mut f = MODULUS;
    let mut g = limbs_from_words(&words);
    let mut len = LIMBS;
    let mut eta = -1i64;
    let mut jac = 0u64;

    for batch in 1..=cap {
        let f0 = (f[0] as u64) | ((f[1] as u64) << 62);
        let g0 = (g[0] as u64) | ((g[1] as u64) << 62);
        let (next_eta, t) = posdivsteps(eta, f0, g0, &mut jac);
        eta = next_eta;
        update_fg(len, &mut f, &mut g, &t);

        // f and g converge to gcd(x, p) = 1. Once f = 1, (g | f) = 1 and the
        // tracked sign is the answer.
        if f[0] == 1 && f[1..len].iter().all(|&limb| limb == 0) {
            return Some((if jac & 1 == 0 { 1 } else { -1 }, batch));
        }

        // Drop the top limb once both values fit without it.
        if len > 1 && f[len - 1] == 0 && g[len - 1] == 0 {
            len -= 1;
        }
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;

    /// Euler's criterion, `x^((p-1)/2)`, computed from the existing
    /// exponentiation chain: `(p-1)/2 = 4 * (p-5)/8 + 2`.
    fn legendre_by_exponentiation(x: &FieldElement51) -> i8 {
        let fe = crate::field::FieldElement::from_bytes(&x.to_bytes());
        if bool::from(fe.is_zero()) {
            return 0;
        }
        let e = &fe.pow_p58().pow2k(2) * &fe.square();
        if e.to_bytes() == FieldElement51::ONE.to_bytes() {
            1
        } else {
            assert_eq!(e.to_bytes(), FieldElement51::MINUS_ONE.to_bytes());
            -1
        }
    }

    #[test]
    #[ignore]
    fn print_convergence_statistics() {
        extern crate std;
        use rand::Rng;
        use std::println;
        let mut rng = rand::rng();
        let mut hist = [0usize; 64];
        let mut worst = 0;
        for _ in 0..20000 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let (_, batches) = jacobi_with_cap(&FieldElement51::from_bytes(&bytes), 60)
                .expect("random inputs converge within 60 batches");
            hist[batches.min(63)] += 1;
            worst = worst.max(batches);
        }
        println!(
            "random: worst {worst} batches, histogram {:?}",
            &hist[..=worst]
        );
        let mut structured = std::vec::Vec::new();
        for bit in 0..255u32 {
            let mut bytes = [0u8; 32];
            bytes[(bit / 8) as usize] = 1 << (bit % 8);
            let power = FieldElement51::from_bytes(&bytes);
            structured.push(power);
            structured.push(&power - &FieldElement51::ONE);
            structured.push(&power + &FieldElement51::ONE);
            structured.push(-&power);
            structured.push(-&(&power - &FieldElement51::ONE));
        }
        for small in 2u64..64 {
            structured.push(FieldElement51([small, 0, 0, 0, 0]));
            structured.push(-&FieldElement51([small, 0, 0, 0, 0]));
        }
        let mut worst = 0;
        let mut unconverged = 0;
        for x in &structured {
            match jacobi_with_cap(x, 400) {
                Some((_, batches)) => worst = worst.max(batches),
                None => unconverged += 1,
            }
        }
        println!(
            "structured: {} inputs, worst {worst} batches, {unconverged} did not converge in 400",
            structured.len()
        );
        // Random inputs of a given bit length: worst batches per length.
        let mut per_len = std::vec::Vec::new();
        for bits in 1..=255u32 {
            let mut worst = 0;
            for _ in 0..40 {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                let top = (bits - 1) as usize;
                for b in bytes.iter_mut().skip(top / 8 + 1) {
                    *b = 0;
                }
                bytes[top / 8] &= (1u16 << (top % 8 + 1)).wrapping_sub(1) as u8;
                bytes[top / 8] |= 1 << (top % 8);
                let x = FieldElement51::from_bytes(&bytes);
                if x.to_bytes() == [0u8; 32] {
                    continue;
                }
                match jacobi_with_cap(&x, 400) {
                    Some((_, batches)) => worst = worst.max(batches),
                    None => worst = 999,
                }
            }
            per_len.push(worst);
        }
        println!("per-bit-length worst batches: {:?}", per_len);
    }

    #[test]
    fn modulus_limbs_encode_p() {
        assert_eq!(limbs_from_words(&P_WORDS), MODULUS);
        for (i, &inv) in NEG_INV64.iter().enumerate() {
            let f = (2 * i + 1) as u64;
            assert_eq!(f.wrapping_mul(u64::from(inv)) & 63, 63, "f = {f}");
        }
    }

    #[test]
    fn small_inputs_match_euler_criterion() {
        use rand::RngExt;
        let mut rng = rand::rng();
        let mut values: std::vec::Vec<u64> = (1..2048).collect();
        values.extend((0..2048).map(|_| rng.random::<u64>()));
        values.extend((0..512).map(|_| rng.random::<u32>() as u64));
        for x in values {
            let fe = FieldElement51([x & ((1 << 51) - 1), x >> 51, 0, 0, 0]);
            assert_eq!(jacobi_small(x), legendre_by_exponentiation(&fe), "x = {x}");
            // Also through the public entry point and its p - x twin.
            assert_eq!(jacobi_vartime(&fe), Some(legendre_by_exponentiation(&fe)));
            assert_eq!(jacobi_vartime(&-&fe), Some(legendre_by_exponentiation(&fe)));
        }
    }

    #[test]
    fn jacobi_matches_euler_criterion() {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut inputs = std::vec![
            FieldElement51::ZERO,
            FieldElement51::ONE,
            FieldElement51::MINUS_ONE,
            FieldElement51([2, 0, 0, 0, 0]),
            FieldElement51([3, 0, 0, 0, 0]),
            FieldElement51([5, 0, 0, 0, 0]),
            FieldElement51([7, 0, 0, 0, 0]),
            FieldElement51([19, 0, 0, 0, 0]),
            crate::constants::SQRT_M1,
            crate::constants::EDWARDS_D,
        ];
        for bit in 0..255u32 {
            let mut bytes = [0u8; 32];
            bytes[(bit / 8) as usize] = 1 << (bit % 8);
            let power = FieldElement51::from_bytes(&bytes);
            inputs.push(power);
            inputs.push(&power - &FieldElement51::ONE);
            inputs.push(&power + &FieldElement51::ONE);
            inputs.push(-&power);
        }
        for _ in 0..8192 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            inputs.push(FieldElement51::from_bytes(&bytes));
        }
        let mut fallbacks = 0;
        for x in inputs {
            match jacobi_vartime(&x) {
                Some(symbol) => assert_eq!(symbol, legendre_by_exponentiation(&x), "x = {x:?}"),
                None => fallbacks += 1,
            }
        }
        // Every tested input converges within the batch cap; a fallback here
        // would mean the cap no longer covers the structured inputs above.
        assert_eq!(fallbacks, 0);
    }
}
