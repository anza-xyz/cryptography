use super::constants::K;
use super::ops::{big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use super::trace::BlockTrace;

/// SHA-512 witness and trace builder for the PoKOS seed-chain AIR.
///
/// `Sha512Circuit` is a namespace (a zero-sized struct with only associated functions)
/// that groups two layers of functionality:
///
/// 1. **Block-level witness** — [`compress_block`](Sha512Circuit::compress_block) runs
///    a single 128-byte block compression and records every intermediate value in a
///    [`BlockTrace`], which is the prover's witness.
///
/// 2. **AIR trace generation** — [`build_plonky3_air_trace`](Sha512Circuit::build_plonky3_air_trace)
///    and [`build_plonky3_preprocessed_trace_from_instance`](Sha512Circuit::build_plonky3_preprocessed_trace_from_instance)
///    convert a `BlockTrace` into the column matrices consumed by Plonky3.
///
/// This crate no longer exposes a generic public SHA-512 API; the active consumer is the
/// internal PoKOS seed-chain proof path.
pub struct Sha512Circuit;

impl Sha512Circuit {
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

        BlockTrace {
            words,
            round_states,
        }
    }
}
