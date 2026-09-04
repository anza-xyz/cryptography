// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.

//! Eight-message multibuffer SHA-512 in AVX-512 intrinsics.
//!
//! One message per 64-bit lane. Lanes of different lengths run to the longest
//! lane's block count with per-lane masked state updates, so a shorter lane
//! freezes after its final padded block.

#![allow(clippy::needless_range_loop)]
// Nightly and stable currently disagree on the requirement of unsafe blocks
// when intrinsics are called inside `#[target_feature]` functions.
#![allow(unused_unsafe)]

use core::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_loadu_si512, _mm512_mask_add_epi64, _mm512_ror_epi64,
    _mm512_set1_epi64, _mm512_shuffle_epi8, _mm512_shuffle_i64x2, _mm512_srli_epi64,
    _mm512_storeu_si512, _mm512_ternarylogic_epi64, _mm512_unpackhi_epi64, _mm512_unpacklo_epi64,
};
use core::mem::MaybeUninit;

use super::field_x8::LANES;

#[rustfmt::skip]
const K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[rustfmt::skip]
const H512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// The SHA-512 block size in bytes.
const BLOCK: usize = 128;

/// Blocks staged per lane: the `R || A` prefix block plus the one or two padding
/// blocks. Everything between them is read where it lies.
const STAGE_BLOCKS: usize = 3;

/// `VPSHUFB` control reversing each 64-bit group, applied per 128-bit lane.
#[rustfmt::skip]
const BSWAP64: [u8; 64] = [
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
];

/// Transpose eight 64-byte lane rows into eight per-word vectors, byte-swapped
/// into the big-endian values the schedule operates on.
#[target_feature(enable = "avx512f,avx512bw")]
#[inline]
unsafe fn transpose_words_x8(rows: &[__m512i; 8], bswap: __m512i) -> [__m512i; 8] {
    unsafe {
        let t0 = _mm512_unpacklo_epi64(rows[0], rows[1]);
        let t1 = _mm512_unpackhi_epi64(rows[0], rows[1]);
        let t2 = _mm512_unpacklo_epi64(rows[2], rows[3]);
        let t3 = _mm512_unpackhi_epi64(rows[2], rows[3]);
        let t4 = _mm512_unpacklo_epi64(rows[4], rows[5]);
        let t5 = _mm512_unpackhi_epi64(rows[4], rows[5]);
        let t6 = _mm512_unpacklo_epi64(rows[6], rows[7]);
        let t7 = _mm512_unpackhi_epi64(rows[6], rows[7]);

        let s0 = _mm512_shuffle_i64x2::<0x88>(t0, t2);
        let s1 = _mm512_shuffle_i64x2::<0x88>(t1, t3);
        let s2 = _mm512_shuffle_i64x2::<0xdd>(t0, t2);
        let s3 = _mm512_shuffle_i64x2::<0xdd>(t1, t3);
        let s4 = _mm512_shuffle_i64x2::<0x88>(t4, t6);
        let s5 = _mm512_shuffle_i64x2::<0x88>(t5, t7);
        let s6 = _mm512_shuffle_i64x2::<0xdd>(t4, t6);
        let s7 = _mm512_shuffle_i64x2::<0xdd>(t5, t7);

        [
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0x88>(s0, s4), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0x88>(s1, s5), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0x88>(s2, s6), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0x88>(s3, s7), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0xdd>(s0, s4), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0xdd>(s1, s5), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0xdd>(s2, s6), bswap),
            _mm512_shuffle_epi8(_mm512_shuffle_i64x2::<0xdd>(s3, s7), bswap),
        ]
    }
}

/// Compute the eight digests `SHA-512(R_l || A_l || M_l)`.
///
/// # Safety
///
/// The caller must have verified AVX-512 support (`ifma_x8::available()`,
/// which covers the `avx512f` and `avx512bw` operations used here).
#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) unsafe fn challenge_digests_x8(
    r_bytes: &[[u8; 32]; LANES],
    a_bytes: &[[u8; 32]; LANES],
    msgs: &[&[u8]; LANES],
) -> [[u8; 64]; LANES] {
    unsafe {
        // `R || A` is half a block, so only block 0 and the padded tail are staged.
        let mut stage = [[MaybeUninit::<u8>::uninit(); STAGE_BLOCKS * BLOCK]; LANES];
        let mut blocks = [0usize; LANES];
        let mut pad_block = [0usize; LANES];
        let mut pad_slot = [0usize; LANES];
        let mut max_blocks = 0usize;

        for l in 0..LANES {
            let msg = msgs[l];
            let len = 64 + msg.len();
            let padded = (len + 1 + 16).div_ceil(BLOCK) * BLOCK;
            blocks[l] = padded / BLOCK;
            max_blocks = max_blocks.max(blocks[l]);

            // The block holding the 0x80 marker, and where it is staged.
            let pb = len / BLOCK;
            pad_block[l] = pb;
            pad_slot[l] = usize::from(pb != 0);

            let base = stage[l].as_mut_ptr().cast::<u8>();
            core::ptr::copy_nonoverlapping(r_bytes[l].as_ptr(), base, 32);
            core::ptr::copy_nonoverlapping(a_bytes[l].as_ptr(), base.add(32), 32);
            core::ptr::copy_nonoverlapping(msg.as_ptr(), base.add(64), msg.len().min(BLOCK - 64));

            let pad = base.add(pad_slot[l] * BLOCK);
            let used = len - pb * BLOCK;
            if pb != 0 {
                let off = pb * BLOCK - 64;
                core::ptr::copy_nonoverlapping(msg.as_ptr().add(off), pad, used);
            }
            *pad.add(used) = 0x80;
            core::ptr::write_bytes(pad.add(used + 1), 0, BLOCK - used - 1);

            // The 128-bit length lands in the final block, one past the marker's
            // block when the marker left no room.
            let last = base.add((pad_slot[l] + blocks[l] - 1 - pb) * BLOCK);
            if last != pad {
                core::ptr::write_bytes(last, 0, BLOCK - 8);
            }
            core::ptr::copy_nonoverlapping(
                ((len as u64) * 8).to_be_bytes().as_ptr(),
                last.add(BLOCK - 8),
                8,
            );
        }

        let zero_block = [0u8; BLOCK];
        let mut stage_base = [core::ptr::null::<u8>(); LANES];
        let mut msg_base = [core::ptr::null::<u8>(); LANES];
        for l in 0..LANES {
            stage_base[l] = stage[l].as_ptr().cast::<u8>();
            msg_base[l] = msgs[l].as_ptr();
        }

        let bswap = _mm512_loadu_si512(BSWAP64.as_ptr() as *const _);
        let mut state: [__m512i; 8] = [
            _mm512_set1_epi64(H512[0] as i64),
            _mm512_set1_epi64(H512[1] as i64),
            _mm512_set1_epi64(H512[2] as i64),
            _mm512_set1_epi64(H512[3] as i64),
            _mm512_set1_epi64(H512[4] as i64),
            _mm512_set1_epi64(H512[5] as i64),
            _mm512_set1_epi64(H512[6] as i64),
            _mm512_set1_epi64(H512[7] as i64),
        ];

        for b in 0..max_blocks {
            // Lanes still inside their stream this block.
            let mut active: u8 = 0;
            let mut block = [zero_block.as_ptr(); LANES];
            for l in 0..LANES {
                if b >= blocks[l] {
                    continue;
                }
                active |= 1 << l;
                block[l] = if b == 0 {
                    stage_base[l]
                } else if b >= pad_block[l] {
                    stage_base[l].add((pad_slot[l] + b - pad_block[l]) * BLOCK)
                } else {
                    msg_base[l].add(b * BLOCK - 64)
                };
            }

            // Message schedule ring, gathered by transposing the lane rows.
            let mut w = [_mm512_set1_epi64(0); 16];
            for half in 0..2 {
                let mut rows = [_mm512_set1_epi64(0); LANES];
                for l in 0..LANES {
                    rows[l] = _mm512_loadu_si512(block[l].add(half * 64) as *const _);
                }
                w[half * 8..half * 8 + 8].copy_from_slice(&transpose_words_x8(&rows, bswap));
            }

            let mut a = state[0];
            let mut bb = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            for t in 0..80 {
                if t >= 16 {
                    // w[t] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16]
                    let w2 = w[(t + 14) % 16];
                    let w15 = w[(t + 1) % 16];
                    let s1 = _mm512_ternarylogic_epi64::<0x96>(
                        _mm512_ror_epi64::<19>(w2),
                        _mm512_ror_epi64::<61>(w2),
                        _mm512_srli_epi64::<6>(w2),
                    );
                    let s0 = _mm512_ternarylogic_epi64::<0x96>(
                        _mm512_ror_epi64::<1>(w15),
                        _mm512_ror_epi64::<8>(w15),
                        _mm512_srli_epi64::<7>(w15),
                    );
                    w[t % 16] = _mm512_add_epi64(
                        _mm512_add_epi64(w[t % 16], w[(t + 9) % 16]),
                        _mm512_add_epi64(s0, s1),
                    );
                }

                let big_s1 = _mm512_ternarylogic_epi64::<0x96>(
                    _mm512_ror_epi64::<14>(e),
                    _mm512_ror_epi64::<18>(e),
                    _mm512_ror_epi64::<41>(e),
                );
                let ch = _mm512_ternarylogic_epi64::<0xCA>(e, f, g);
                let t1 = _mm512_add_epi64(
                    _mm512_add_epi64(h, big_s1),
                    _mm512_add_epi64(
                        _mm512_add_epi64(ch, _mm512_set1_epi64(K64[t] as i64)),
                        w[t % 16],
                    ),
                );
                let big_s0 = _mm512_ternarylogic_epi64::<0x96>(
                    _mm512_ror_epi64::<28>(a),
                    _mm512_ror_epi64::<34>(a),
                    _mm512_ror_epi64::<39>(a),
                );
                let maj = _mm512_ternarylogic_epi64::<0xE8>(a, bb, c);
                let t2 = _mm512_add_epi64(big_s0, maj);

                h = g;
                g = f;
                f = e;
                e = _mm512_add_epi64(d, t1);
                d = c;
                c = bb;
                bb = a;
                a = _mm512_add_epi64(t1, t2);
            }

            // Masked feed-forward: only active lanes absorb this block.
            state[0] = _mm512_mask_add_epi64(state[0], active, state[0], a);
            state[1] = _mm512_mask_add_epi64(state[1], active, state[1], bb);
            state[2] = _mm512_mask_add_epi64(state[2], active, state[2], c);
            state[3] = _mm512_mask_add_epi64(state[3], active, state[3], d);
            state[4] = _mm512_mask_add_epi64(state[4], active, state[4], e);
            state[5] = _mm512_mask_add_epi64(state[5], active, state[5], f);
            state[6] = _mm512_mask_add_epi64(state[6], active, state[6], g);
            state[7] = _mm512_mask_add_epi64(state[7], active, state[7], h);
        }

        // Extract per-lane big-endian digests.
        let mut words = [[0u64; LANES]; 8];
        for i in 0..8 {
            _mm512_storeu_si512(words[i].as_mut_ptr() as *mut _, state[i]);
        }
        core::array::from_fn(|l| {
            let mut digest = [0u8; 64];
            for i in 0..8 {
                digest[i * 8..i * 8 + 8].copy_from_slice(&words[i][l].to_be_bytes());
            }
            digest
        })
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use sha2::{Digest, Sha512};

    // digests match the sha2 crate across padding boundaries and mixed lengths
    #[test]
    fn digests_match_sha2() {
        if !crate::backend::lanes::ifma_x8::available() {
            return;
        }

        // Hashed length is 64 + msg len, so these straddle both padding boundaries.
        let msg_lens: [usize; LANES] = [0, 1, 47, 48, 63, 175, 176, 1232];
        let msgs_data: Vec<Vec<u8>> = msg_lens
            .iter()
            .enumerate()
            .map(|(i, &n)| alloc::vec![i as u8 ^ 0xA7; n])
            .collect();

        let r_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| [l as u8 + 1; 32]);
        let a_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| [l as u8 + 101; 32]);
        let msgs: [&[u8]; LANES] = core::array::from_fn(|l| msgs_data[l].as_slice());

        let digests = unsafe { challenge_digests_x8(&r_bytes, &a_bytes, &msgs) };

        for l in 0..LANES {
            let expected = Sha512::new()
                .chain_update(r_bytes[l])
                .chain_update(a_bytes[l])
                .chain_update(msgs[l])
                .finalize();
            assert_eq!(digests[l][..], expected[..], "lane {l}");
        }
    }

    // digests match sha2 with every staging boundary in every lane position
    #[test]
    fn digests_match_sha2_ragged() {
        if !crate::backend::lanes::ifma_x8::available() {
            return;
        }

        const LENS: [usize; 18] = [
            0, 1, 47, 48, 63, 64, 65, 111, 127, 128, 129, 175, 176, 191, 192, 200, 1232, 4096,
        ];

        for shift in 0..LENS.len() {
            let msg_lens: [usize; LANES] =
                core::array::from_fn(|l| LENS[(l * 5 + shift) % LENS.len()]);
            let msgs_data: Vec<Vec<u8>> = msg_lens
                .iter()
                .enumerate()
                .map(|(i, &n)| (0..n).map(|j| (i * 31 + j) as u8).collect())
                .collect();

            let r_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| [(l * 7 + shift) as u8; 32]);
            let a_bytes: [[u8; 32]; LANES] =
                core::array::from_fn(|l| [(l * 13 + shift + 3) as u8; 32]);
            let msgs: [&[u8]; LANES] = core::array::from_fn(|l| msgs_data[l].as_slice());

            let digests = unsafe { challenge_digests_x8(&r_bytes, &a_bytes, &msgs) };

            for l in 0..LANES {
                let expected = Sha512::new()
                    .chain_update(r_bytes[l])
                    .chain_update(a_bytes[l])
                    .chain_update(msgs[l])
                    .finalize();
                assert_eq!(
                    digests[l][..],
                    expected[..],
                    "shift {shift} lane {l} len {}",
                    msg_lens[l]
                );
            }
        }
    }
}
