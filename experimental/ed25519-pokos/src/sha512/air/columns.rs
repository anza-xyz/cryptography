//! Column index constants and helper functions for the SHA-512 AIR trace.
//!
//! The main AIR trace has `AIR_WIDTH` columns per row.  This module defines a name for
//! every column (or column group) and provides accessor functions that compute the
//! concrete column index from logical identifiers (word index, limb index, bit index,
//! etc.).
//!
//! ## Column layout (in order)
//!
//! ```text
//! ┌─ Limbs ────────────────────────── cols 0 – 63 ──────────────────────────────────────┐
//! │  16 words × 4 limbs (16-bit each) = 64 columns                                      │
//! ├─ Carries ───────────────────────────────────────────────────────────────────────────┤
//! │  Carry_T1 (4), Carry_T2 (4), Carry_A (4), Carry_E (4)  = 16 columns               │
//! ├─ Lags ──────────────────────────────────────────────────────────────────────────────┤
//! │  16 previous W values (ring buffer), stored as 4 limbs each = 64 columns            │
//! ├─ Schedule carries ──────────────────────────────────────────────────────────────────┤
//! │  4 carries for W recurrence = 4 columns                                            │
//! ├─ Bit decompositions ────────────────────────────────────────────────────────────────┤
//! │  64 bits × {A, B, C, E, F, G} = 384 columns                                        │
//! │  64 bits × {lag1, lag14} = 128 columns                                               │
//! ├─ Range-proof bits ──────────────────────────────────────────────────────────────────┤
//! │  RANGE_SOURCES sources × 16 bits each (D/H/W/K/T1/T2 limbs)                         │
//! ├─ Carry bits ────────────────────────────────────────────────────────────────────────┤
//! │  Minimal-width carry bit decompositions (T1=3 bits, T2/A/E=1 bit, sched=2 bits)   │
//! ├─ Preprocessed columns (at the tail — shared with the preprocessed trace) ───────────┤
//! │  PREP_BLOCK_START_SELECTOR_COL — 1 at block-start rows, 0 elsewhere                  │
//! │  PREP_TRANSITION_SELECTOR_COL  — 1 where row-to-next transition is enforced          │
//! │  PREP_ROUND_SELECTOR_COL       — 1 in rounds 0..79, 0 elsewhere                      │
//! │  PREP_INIT_W_SELECTOR_COL      — 1 in rows 0..15, 0 elsewhere                        │
//! │  PREP_FINAL_SELECTOR_COL       — 1 in row 80 only                                    │
//! │  PREP_SEGMENT_* selectors      — fixed-role metadata for the seed-chain AIR          │
//! └─────────────────────────────────────────────────────────────────────────────────────┘
//! ```

// ─── Trace dimensions ────────────────────────────────────────────────────────

/// Total number of rows in the AIR trace (must be a power of two).
///
/// Rows 0–79 are the 80 SHA-512 compression rounds.
/// Row 80 holds the post-round working state and the public value bindings.
/// Rows 81–127 are degenerate padding rows.
pub(super) const TRACE_ROWS: usize = 128;

/// First row index that is not a real SHA-512 round (row 80 = final state, rows 81+ = padding).
pub(super) const SHA_ROUNDS_PLUS_INIT: usize = 81;

// ─── Logical word ids ────────────────────────────────────────────────────────

/// Logical word id for working variable `a`.
pub(super) const WORD_A: usize = 0;
/// Logical word id for working variable `b` (equals previous round's `a`).
pub(super) const WORD_B: usize = 1;
/// Logical word id for working variable `c` (equals previous round's `b`).
pub(super) const WORD_C: usize = 2;
/// Logical word id for working variable `d` (equals previous round's `c`).
pub(super) const WORD_D: usize = 3;
/// Logical word id for working variable `e`.
pub(super) const WORD_E: usize = 4;
/// Logical word id for working variable `f` (equals previous round's `e`).
pub(super) const WORD_F: usize = 5;
/// Logical word id for working variable `g` (equals previous round's `f`).
pub(super) const WORD_G: usize = 6;
/// Logical word id for working variable `h` (equals previous round's `g`).
pub(super) const WORD_H: usize = 7;
/// Logical word id for current message schedule word W[i].
pub(super) const WORD_W: usize = 8;
/// Logical word id for round constant K[i].
pub(super) const WORD_K: usize = 9;
/// Logical word id for Σ0(a).
pub(super) const WORD_SIGMA0: usize = 10;
/// Logical word id for Σ1(e).
pub(super) const WORD_SIGMA1: usize = 11;
/// Logical word id for Ch(e, f, g).
pub(super) const WORD_CH: usize = 12;
/// Logical word id for Maj(a, b, c).
pub(super) const WORD_MAJ: usize = 13;
/// Logical word id for T1.
pub(super) const WORD_T1: usize = 14;
/// Logical word id for T2.
pub(super) const WORD_T2: usize = 15;
/// Total number of logical words tracked in limbs.
pub(super) const WORD_COUNT: usize = 16;

// ─── Limb columns ────────────────────────────────────────────────────────────

/// Number of 16-bit limbs per 64-bit word.
pub(super) const LIMBS_PER_WORD: usize = 4;

/// First column of the limb section.
///
/// Limbs are stored as `LIMB_BASE + word * LIMBS_PER_WORD + limb` where `limb ∈ 0..4`
/// with limb 0 being the least significant 16 bits.  Use [`limb_col`] to compute.
pub(super) const LIMB_BASE: usize = 0;

// ─── Carry columns ───────────────────────────────────────────────────────────

/// First carry column for the T1 = h + Σ1(e) + Ch + K + W limb-wise addition.
///
/// Four consecutive columns, one per limb (least to most significant).
pub(super) const CARRY_T1_BASE: usize = WORD_COUNT * LIMBS_PER_WORD;

/// First carry column for the T2 = Σ0(a) + Maj limb-wise addition.
pub(super) const CARRY_T2_BASE: usize = CARRY_T1_BASE + LIMBS_PER_WORD;

/// First carry column for the new-`a` addition: A = T1 + T2 (cross-row).
pub(super) const CARRY_A_BASE: usize = CARRY_T2_BASE + LIMBS_PER_WORD;

/// First carry column for the new-`e` addition: E = d + T1 (cross-row).
pub(super) const CARRY_E_BASE: usize = CARRY_A_BASE + LIMBS_PER_WORD;

// ─── Lag columns (message schedule history) ──────────────────────────────────

/// Number of previous W values tracked in the lag ring buffer.
///
/// The SHA-512 schedule recurrence references W[i−2], W[i−7], W[i−15], and W[i−16],
/// so the circuit needs to remember the last 16 W values.
pub(super) const LAG_COUNT: usize = 16;

/// First column of the lag-word limb section.
///
/// Each lag word is also decomposed into 4 × 16-bit limbs for range-proof purposes.
/// Use [`lag_limb_col`] to compute.
pub(super) const LAG_LIMB_BASE: usize = CARRY_E_BASE + LIMBS_PER_WORD;

// ─── Schedule carry columns ───────────────────────────────────────────────────

/// First carry column for the 4-operand message schedule recurrence addition.
///
/// The recurrence W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16] requires
/// four carry columns (one per 16-bit limb).
pub(super) const SCHED_CARRY_BASE: usize = LAG_LIMB_BASE + LAG_COUNT * LIMBS_PER_WORD;

// ─── Bit-decomposition columns ────────────────────────────────────────────────

/// First bit column for the Boolean decomposition of `a`.
pub(super) const BIT_A_BASE: usize = SCHED_CARRY_BASE + LIMBS_PER_WORD;
/// First bit column for the Boolean decomposition of `b`.
pub(super) const BIT_B_BASE: usize = BIT_A_BASE + 64;
/// First bit column for the Boolean decomposition of `c`.
pub(super) const BIT_C_BASE: usize = BIT_B_BASE + 64;
/// First bit column for the Boolean decomposition of `e`.
pub(super) const BIT_E_BASE: usize = BIT_C_BASE + 64;
/// First bit column for the Boolean decomposition of `f`.
pub(super) const BIT_F_BASE: usize = BIT_E_BASE + 64;
/// First bit column for the Boolean decomposition of `g`.
pub(super) const BIT_G_BASE: usize = BIT_F_BASE + 64;

// ─── Range-proof columns ─────────────────────────────────────────────────────

/// Words whose limbs are range-proved through the generic 16-bit range-bit section.
///
/// Limbs of `A,B,C,E,F,G` are constrained directly from their 64-bit Boolean
/// decompositions in the AIR, so they are excluded from this set.
pub(super) const RANGED_WORDS: [usize; 6] = [WORD_D, WORD_H, WORD_W, WORD_K, WORD_T1, WORD_T2];

/// Number of range-proof sources contributed by word limbs.
pub(super) const RANGED_WORD_SOURCES: usize = RANGED_WORDS.len() * LIMBS_PER_WORD;

/// Number of 16-bit values that receive a generic range proof (selected word limbs only).
pub(super) const RANGE_SOURCES: usize = RANGED_WORD_SOURCES;

/// Number of Boolean bits allocated per range-proof source (= 16, covering 0..65535).
pub(super) const RANGE_BITS_PER_SOURCE: usize = 16;

/// First bit column for the Boolean decomposition of lag word W[i-2] (lag index 1).
pub(super) const LAG1_BIT_BASE: usize = BIT_G_BASE + 64;
/// First bit column for the Boolean decomposition of lag word W[i-15] (lag index 14).
pub(super) const LAG14_BIT_BASE: usize = LAG1_BIT_BASE + 64;

/// First column of the range-proof bit section.
pub(super) const RANGE_BIT_BASE: usize = LAG14_BIT_BASE + 64;

/// First column of carry-bit decomposition section.
pub(super) const CARRY_BIT_BASE: usize = RANGE_BIT_BASE + RANGE_SOURCES * RANGE_BITS_PER_SOURCE;

/// First carry-bit column for T1 carry limbs (3 bits per limb).
pub(super) const CARRY_T1_BIT_BASE: usize = CARRY_BIT_BASE;
/// First carry-bit column for T2 carry limbs (1 bit per limb).
pub(super) const CARRY_T2_BIT_BASE: usize = CARRY_T1_BIT_BASE + LIMBS_PER_WORD * 3;
/// First carry-bit column for A carry limbs (1 bit per limb).
pub(super) const CARRY_A_BIT_BASE: usize = CARRY_T2_BIT_BASE + LIMBS_PER_WORD;
/// First carry-bit column for E carry limbs (1 bit per limb).
pub(super) const CARRY_E_BIT_BASE: usize = CARRY_A_BIT_BASE + LIMBS_PER_WORD;
/// First carry-bit column for schedule carry limbs (2 bits per limb).
pub(super) const CARRY_SCHED_BIT_BASE: usize = CARRY_E_BIT_BASE + LIMBS_PER_WORD;

/// First seed-chain segment selector: 1 on commit segment rows, 0 elsewhere.
pub(super) const PREP_SEGMENT_COMMIT_SELECTOR_COL: usize =
    CARRY_SCHED_BIT_BASE + LIMBS_PER_WORD * 2;

/// 1 on derive segment rows, 0 elsewhere.
pub(super) const PREP_SEGMENT_DERIVE_SELECTOR_COL: usize = PREP_SEGMENT_COMMIT_SELECTOR_COL + 1;

/// 1 on hash-of-sk segment rows, 0 elsewhere.
pub(super) const PREP_SEGMENT_HASH_SELECTOR_COL: usize = PREP_SEGMENT_DERIVE_SELECTOR_COL + 1;

/// 1 on row 80 of the commit segment, 0 elsewhere.
pub(super) const PREP_COMMIT_FINAL_SELECTOR_COL: usize = PREP_SEGMENT_HASH_SELECTOR_COL + 1;

/// 1 on row 80 of the derive segment, 0 elsewhere.
pub(super) const PREP_DERIVE_FINAL_SELECTOR_COL: usize = PREP_COMMIT_FINAL_SELECTOR_COL + 1;

/// 1 on row 80 of the hash-of-sk segment, 0 elsewhere.
pub(super) const PREP_HASH_FINAL_SELECTOR_COL: usize = PREP_DERIVE_FINAL_SELECTOR_COL + 1;

/// 1 on rows 4..7 of each seed-chain segment, where W carries the private payload.
pub(super) const PREP_PAYLOAD_WORD_SELECTOR_COL: usize = PREP_HASH_FINAL_SELECTOR_COL + 1;

/// 1 on fixed W[0..15] rows except payload rows, for the seed-chain AIR.
pub(super) const PREP_FIXED_INIT_W_SELECTOR_COL: usize = PREP_PAYLOAD_WORD_SELECTOR_COL + 1;

/// 1 only on row 4 of each seed-chain segment.
pub(super) const PREP_PAYLOAD_WORD0_SELECTOR_COL: usize = PREP_FIXED_INIT_W_SELECTOR_COL + 1;

/// 1 only on row 5 of each seed-chain segment.
pub(super) const PREP_PAYLOAD_WORD1_SELECTOR_COL: usize = PREP_PAYLOAD_WORD0_SELECTOR_COL + 1;

/// 1 only on row 6 of each seed-chain segment.
pub(super) const PREP_PAYLOAD_WORD2_SELECTOR_COL: usize = PREP_PAYLOAD_WORD1_SELECTOR_COL + 1;

/// 1 only on row 7 of each seed-chain segment.
pub(super) const PREP_PAYLOAD_WORD3_SELECTOR_COL: usize = PREP_PAYLOAD_WORD2_SELECTOR_COL + 1;

/// Hidden witness columns holding the 32-byte seed as four 64-bit words.
pub(super) const PRIVATE_SEED_LIMB_BASE: usize = PREP_PAYLOAD_WORD3_SELECTOR_COL + 1;

/// Hidden witness columns holding the 32-byte derived sk_seed as four 64-bit words.
pub(super) const PRIVATE_SK_LIMB_BASE: usize = PRIVATE_SEED_LIMB_BASE + 4 * LIMBS_PER_WORD;

/// Total number of columns in the AIR trace (main and preprocessed share the same width).
pub(super) const AIR_WIDTH: usize = PRIVATE_SK_LIMB_BASE + 4 * LIMBS_PER_WORD;

// ─── Preprocessed selector columns (at the tail of the shared column space) ──

/// Preprocessed selector: 1 on the first row of each real block segment, 0 elsewhere.
pub(super) const PREP_BLOCK_START_SELECTOR_COL: usize = AIR_WIDTH - 5;

/// Preprocessed selector: 1 when transition constraints are active for this row.
///
/// This is set on rows whose `next` row belongs to the same real block segment.
pub(super) const PREP_TRANSITION_SELECTOR_COL: usize = AIR_WIDTH - 4;

/// Preprocessed selector: 1 for rows 0..79 (active SHA-512 rounds), 0 elsewhere.
///
/// Guards constraints that only apply during real compression rounds (e.g. Σ0/Σ1
/// bit decomposition checks, T1/T2 addition constraints).
pub(super) const PREP_ROUND_SELECTOR_COL: usize = AIR_WIDTH - 3;

/// Preprocessed selector: 1 for rows 0..15 (initial W words from the block), 0 elsewhere.
///
/// Binds the W column to the preprocessed W[0..15] values during the first 16 rows.
pub(super) const PREP_INIT_W_SELECTOR_COL: usize = AIR_WIDTH - 2;

/// Preprocessed selector: 1 only on row 80 (final working state), 0 elsewhere.
///
/// Binds the 8 public values to the working-state columns on this row.
pub(super) const PREP_FINAL_SELECTOR_COL: usize = AIR_WIDTH - 1;

// ─── Index accessor functions ─────────────────────────────────────────────────

/// Returns the column index for `limb` (0–3, LSB first) of `word` (0–15).
pub(super) fn limb_col(word: usize, limb: usize) -> usize {
    LIMB_BASE + word * LIMBS_PER_WORD + limb
}

/// Returns the column index for `limb` (0–3) of lag word `lag`.
pub(super) fn lag_limb_col(lag: usize, limb: usize) -> usize {
    LAG_LIMB_BASE + lag * LIMBS_PER_WORD + limb
}

/// Returns the **column** index of range-proof source `source`.
///
/// Maps logical source indices to selected word limbs (`D/H/W/K/T1/T2`) in the
/// concrete column that holds the 16-bit value being range-proved.  Used by the
/// constraint system to assert `source_col == Σ bit_col[source][k] * 2^k`.
pub(super) fn range_source_col(source: usize) -> usize {
    if source < RANGED_WORD_SOURCES {
        let word_idx = source / LIMBS_PER_WORD;
        let limb = source % LIMBS_PER_WORD;
        limb_col(RANGED_WORDS[word_idx], limb)
    } else {
        unreachable!("range sources only include selected word limbs");
    }
}

/// Returns the column index for bit `bit` (0 = LSB) of range-proof source `source`.
pub(super) fn range_bit_col(source: usize, bit: usize) -> usize {
    RANGE_BIT_BASE + source * RANGE_BITS_PER_SOURCE + bit
}

/// Returns the number of carry bits allocated for `carry_col`.
pub(super) fn carry_bit_width(carry_col: usize) -> usize {
    if (CARRY_T1_BASE..CARRY_T2_BASE).contains(&carry_col) {
        3
    } else if (CARRY_T2_BASE..LAG_LIMB_BASE).contains(&carry_col) {
        1
    } else if (SCHED_CARRY_BASE..BIT_A_BASE).contains(&carry_col) {
        2
    } else {
        unreachable!("carry_col is out of carry column ranges");
    }
}

/// Returns the carry-bit column index for bit `bit` of `carry_col`.
pub(super) fn carry_bit_col(carry_col: usize, bit: usize) -> usize {
    if (CARRY_T1_BASE..CARRY_T2_BASE).contains(&carry_col) {
        CARRY_T1_BIT_BASE + (carry_col - CARRY_T1_BASE) * 3 + bit
    } else if (CARRY_T2_BASE..CARRY_A_BASE).contains(&carry_col) {
        CARRY_T2_BIT_BASE + (carry_col - CARRY_T2_BASE) + bit
    } else if (CARRY_A_BASE..CARRY_E_BASE).contains(&carry_col) {
        CARRY_A_BIT_BASE + (carry_col - CARRY_A_BASE) + bit
    } else if (CARRY_E_BASE..LAG_LIMB_BASE).contains(&carry_col) {
        CARRY_E_BIT_BASE + (carry_col - CARRY_E_BASE) + bit
    } else if (SCHED_CARRY_BASE..BIT_A_BASE).contains(&carry_col) {
        CARRY_SCHED_BIT_BASE + (carry_col - SCHED_CARRY_BASE) * 2 + bit
    } else {
        unreachable!("carry_col is out of carry column ranges");
    }
}

pub(super) fn private_seed_limb_col(word: usize, limb: usize) -> usize {
    PRIVATE_SEED_LIMB_BASE + word * LIMBS_PER_WORD + limb
}

pub(super) fn private_sk_limb_col(word: usize, limb: usize) -> usize {
    PRIVATE_SK_LIMB_BASE + word * LIMBS_PER_WORD + limb
}

// ─── Test re-exports ──────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) const WORD_W_FOR_TESTS: usize = WORD_W;
#[cfg(test)]
pub(crate) const LIMB_BASE_FOR_TESTS: usize = LIMB_BASE;
#[cfg(test)]
pub(crate) const LIMBS_PER_WORD_FOR_TESTS: usize = LIMBS_PER_WORD;
#[cfg(test)]
pub(crate) const PREP_SEGMENT_COMMIT_SELECTOR_COL_FOR_TESTS: usize =
    PREP_SEGMENT_COMMIT_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_SEGMENT_DERIVE_SELECTOR_COL_FOR_TESTS: usize =
    PREP_SEGMENT_DERIVE_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_SEGMENT_HASH_SELECTOR_COL_FOR_TESTS: usize = PREP_SEGMENT_HASH_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_COMMIT_FINAL_SELECTOR_COL_FOR_TESTS: usize = PREP_COMMIT_FINAL_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_DERIVE_FINAL_SELECTOR_COL_FOR_TESTS: usize = PREP_DERIVE_FINAL_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_HASH_FINAL_SELECTOR_COL_FOR_TESTS: usize = PREP_HASH_FINAL_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_PAYLOAD_WORD_SELECTOR_COL_FOR_TESTS: usize = PREP_PAYLOAD_WORD_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PREP_FIXED_INIT_W_SELECTOR_COL_FOR_TESTS: usize = PREP_FIXED_INIT_W_SELECTOR_COL;
#[cfg(test)]
pub(crate) const PRIVATE_SEED_LIMB_BASE_FOR_TESTS: usize = PRIVATE_SEED_LIMB_BASE;
#[cfg(test)]
pub(crate) const PRIVATE_SK_LIMB_BASE_FOR_TESTS: usize = PRIVATE_SK_LIMB_BASE;
