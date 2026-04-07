use super::constants::{INITIAL_STATE, K};
use super::ops::{big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use super::trace::BlockTrace;

/// Reference SHA-512 implementation and AIR witness generator.
///
/// `Sha512Circuit` is a namespace (a zero-sized struct with only associated functions)
/// that groups three layers of functionality:
///
/// 1. **Reference SHA-512** — [`hash`](Sha512Circuit::hash) produces the standard
///    64-byte digest for any message, matching the FIPS 180-4 specification.
///
/// 2. **Block-level witness** — [`compress_block`](Sha512Circuit::compress_block) runs
///    a single 128-byte block compression and records every intermediate value in a
///    [`BlockTrace`], which is the prover's witness.
///
/// 3. **AIR trace generation** — [`build_plonky3_air_trace`](Sha512Circuit::build_plonky3_air_trace)
///    and [`build_plonky3_preprocessed_trace_from_instance`](Sha512Circuit::build_plonky3_preprocessed_trace_from_instance)
///    convert a `BlockTrace` into the column matrices consumed by Plonky3.
///
/// In this crate the main consumer is the internal seed-chain proof path, rather than a
/// generic public SHA-512 proof API.
pub struct Sha512Circuit;

impl Sha512Circuit {
    /// Computes the SHA-512 digest of `message`.
    ///
    /// This is a full, standard-compliant SHA-512 hash: the message is padded per
    /// FIPS 180-4 §5.1.2, split into 128-byte blocks, and each block is compressed
    /// in sequence starting from [`crate::INITIAL_STATE`].
    ///
    /// # Returns
    ///
    /// The 64-byte (512-bit) digest as a big-endian byte array.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sha512_circuit::Sha512Circuit;
    ///
    /// let digest = Sha512Circuit::hash(b"abc");
    /// // digest equals the well-known SHA-512("abc") test vector
    /// ```
    pub fn hash(message: &[u8]) -> [u8; 64] {
        let mut state = INITIAL_STATE;
        for block in Self::padded_blocks(message) {
            let trace = Self::compress_block(&state, &block);
            state = trace.output_state;
        }

        Self::state_to_digest(&state)
    }

    /// Pads `message` per the SHA-512 Merkle–Damgård spec and returns the resulting blocks.
    ///
    /// The padding algorithm (FIPS 180-4 §5.1.2):
    /// 1. Append a single `0x80` byte.
    /// 2. Append zero bytes until `(length + 16) % 128 == 0`.
    /// 3. Append the original bit-length as a 128-bit big-endian integer.
    ///
    /// The resulting byte slice is guaranteed to be a multiple of 128 bytes; this
    /// function splits it into fixed-size `[u8; 128]` blocks.
    ///
    /// # Returns
    ///
    /// A `Vec` of 128-byte blocks, length ≥ 1 (even the empty message produces one block).
    pub fn padded_blocks(message: &[u8]) -> Vec<[u8; 128]> {
        pad_message(message)
            .chunks_exact(128)
            .map(|chunk| chunk.try_into().expect("block size is 128"))
            .collect()
    }

    /// Serialises a SHA-512 working state to a 64-byte big-endian digest.
    ///
    /// Each of the 8 `u64` words is written in big-endian byte order, yielding
    /// 8 × 8 = 64 bytes.  The result is identical to the final output of
    /// [`hash`](Sha512Circuit::hash) when called with the post-feed-forward state.
    pub fn state_to_digest(state: &[u64; 8]) -> [u8; 64] {
        let mut out = [0_u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(state.iter().copied()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Runs one SHA-512 block compression and records the full execution trace.
    ///
    /// Given an 8-word chaining `state` and a 128-byte `block`, this function:
    ///
    /// 1. Parses `block` into 16 big-endian 64-bit words W[0..15].
    /// 2. Expands the message schedule to W[0..79] using the σ0/σ1 recurrence.
    /// 3. Executes 80 rounds of the SHA-512 compression function, recording the
    ///    working state `[a,b,c,d,e,f,g,h]` after each round.
    /// 4. Applies the feed-forward addition: `output[i] = state[i] + working[i]` (mod 2⁶⁴).
    ///
    /// # Returns
    ///
    /// A [`BlockTrace`] containing:
    /// * `words`        — the full 80-word message schedule.
    /// * `round_states` — working state at each of the 81 boundaries (before round 0
    ///   through after round 79).
    /// * `output_state` — the chaining value after feed-forward.
    ///
    /// The `BlockTrace` is the prover's witness and is consumed by
    /// [`build_plonky3_air_trace`](Sha512Circuit::build_plonky3_air_trace).
    pub fn compress_block(state: &[u64; 8], block: &[u8; 128]) -> BlockTrace {
        let mut words = [0_u64; 80];
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            words[i] = u64::from_be_bytes(chunk.try_into().expect("word size is 8"));
        }
        for i in 16..80 {
            words[i] = small_sigma1(words[i - 2])
                .wrapping_add(words[i - 7])
                .wrapping_add(small_sigma0(words[i - 15]))
                .wrapping_add(words[i - 16]);
        }

        let mut round_states = [[0_u64; 8]; 81];
        round_states[0] = *state;

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(words[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            round_states[i + 1] = [a, b, c, d, e, f, g, h];
        }

        let output_state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];

        BlockTrace {
            words,
            round_states,
            output_state,
        }
    }
}

/// Pads `message` to a multiple of 128 bytes following the SHA-512 Merkle–Damgård scheme.
///
/// Layout after padding:
/// ```text
/// [message bytes] [0x80] [zero bytes …] [128-bit big-endian bit-length]
/// ```
/// The total length is always a multiple of 128 and at least 128 bytes.
fn pad_message(message: &[u8]) -> Vec<u8> {
    let bit_len = (message.len() as u128) * 8;

    let mut out = Vec::with_capacity(((message.len() + 17).div_ceil(128)) * 128);
    out.extend_from_slice(message);
    out.push(0x80);

    while (out.len() + 16) % 128 != 0 {
        out.push(0);
    }

    out.extend_from_slice(&bit_len.to_be_bytes());
    out
}
