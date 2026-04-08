/// Full execution witness for one SHA-512 block compression.
///
/// `BlockTrace` captures every intermediate value produced during the compression of a
/// single 128-byte message block.  It is produced by [`crate::sha512::Sha512Circuit::compress_block`]
/// and consumed by [`crate::sha512::Sha512Circuit::build_plonky3_air_trace`] to populate
/// the AIR witness matrix.
///
/// ## Lifecycle
///
/// 1. The prover calls `compress_block` to obtain a `BlockTrace`.
/// 2. The `BlockTrace` is passed to `build_plonky3_air_trace`, which lays out all witness
///    columns (working state words, limb decompositions, carry bits, etc.).
/// 3. The resulting [`p3_matrix::dense::RowMajorMatrix`] is handed to the Plonky3 prover.
///
/// ## Verification without a STARK
///
#[derive(Clone, Debug)]
pub struct BlockTrace {
    /// The expanded message schedule W[0..79].
    ///
    /// * W[0..15]  — parsed directly from the 128-byte block (big-endian, 8 bytes per word).
    /// * W[16..79] — derived via the recurrence
    ///   `W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]` (mod 2⁶⁴).
    pub words: [u64; 80],

    /// Working state snapshots at every round boundary, indexed 0 through 80.
    ///
    /// * `round_states[0]` equals the input chaining state (the state before any rounds).
    /// * `round_states[i+1]` is the state immediately after applying round `i`.
    /// * `round_states[80]` is the working state after all 80 rounds, **before**
    ///   the feed-forward addition.
    ///
    /// The AIR binds `round_states[80]` as the 8 public values of the proof.
    /// The verifier then reconstructs the post-feed-forward digest as
    /// `initial_state + round_states[80]` (component-wise, mod 2⁶⁴).
    pub round_states: [[u64; 8]; 81],
}
