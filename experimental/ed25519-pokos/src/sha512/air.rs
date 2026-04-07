//! Plonky3 AIR definition for the SHA-512 compression circuit.
//!
//! This module stitches together the column layout ([`columns`]), constraint logic
//! ([`constraints`]), and trace-building utilities ([`trace_builder`]) into a single
//! [`Sha512RoundAir`] that Plonky3 can prove and verify.
//!
//! ## Trace layout (128 rows × `AIR_WIDTH` columns)
//!
//! | Row range | Role |
//! |-----------|------|
//! | 0 – 79    | One SHA-512 compression round per row |
//! | 80        | Post-round-80 working state (before feed-forward); public values are bound here |
//! | 81 – 127  | Padding rows — degenerate register-shift rows with W = K = 0 |
//!
//! ## Public values
//!
//! The 8 public values are `round_states[80]` (working state after all 80 rounds).
//! The verifier reconstructs `output_state` externally as `input_state + round_states[80]`
//! (mod 2⁶⁴), so the AIR does **not** constrain the feed-forward addition.
//!
//! ## Preprocessed trace
//!
//! An instance-specific preprocessed trace is committed separately from the main trace.
//! It carries:
//! * The initial working state (a..h) — constant across all rows, used for boundary binding.
//! * The round constant K[i] for each round row.
//! * W[0..15] for the initial 16 rows (before the schedule recurrence takes over).
//! * Four selector columns controlling which constraint groups are active per row.
//!
//! The active seed-chain-specific trace assembly is split into `air/seed_chain.rs` so this file
//! can stay focused on the generic SHA-512 round AIR and base trace layout.

#[path = "air/columns.rs"]
mod columns;
#[path = "air/constraints.rs"]
mod constraints;
#[path = "air/seed_chain.rs"]
mod seed_chain;
#[path = "air/trace_builder.rs"]
mod trace_builder;

use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues, PairBuilder,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::circuit::Sha512Circuit;
use super::constants::{INITIAL_STATE, K};
use super::ops::{bb, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use super::trace::BlockTrace;
use columns::*;
use constraints::*;
use trace_builder::*;

/// The Plonky3 AIR for SHA-512 block compression.
///
/// `Sha512RoundAir` implements the [`Air`] trait and holds the instance-specific
/// preprocessed trace.  The preprocessed trace commits to the initial working state,
/// the 80 round constants, the first 16 message schedule words, and four selector
/// columns.  This allows the STARK verifier to confirm that the prover used the
/// correct instance without re-running the SHA-512 compression.
///
/// ## Construction
///
/// ```ignore
/// use sha512_circuit::Sha512Circuit;
/// use sha512_circuit::Sha512RoundAir;
///
/// let initial_state = sha512_circuit::INITIAL_STATE;
/// let block = [0u8; 128];
/// let preprocessed = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(
///     &initial_state, &block,
/// );
/// let air = Sha512RoundAir::new(preprocessed);
/// ```
///
/// In practice you will not construct this directly — the [`prove_single_block`](crate::prove_single_block)
/// family of functions handle it for you.
#[derive(Clone, Debug)]
pub struct Sha512RoundAir {
    preprocessed: RowMajorMatrix<KoalaBear>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateSeedChainBlocks {
    pub(crate) commit: [u8; 128],
    pub(crate) derive: [u8; 128],
    pub(crate) hash_sk: [u8; 128],
}

impl Sha512RoundAir {
    /// Creates a new [`Sha512RoundAir`] from a precomputed preprocessed trace.
    ///
    /// The `preprocessed` matrix must have been produced by
    /// [`Sha512Circuit::build_plonky3_preprocessed_trace_from_instance`] for the same
    /// `(initial_state, block)` pair that will be proved / verified.
    pub fn new(preprocessed: RowMajorMatrix<KoalaBear>) -> Self {
        Self { preprocessed }
    }
}

impl BaseAir<KoalaBear> for Sha512RoundAir {
    fn width(&self) -> usize {
        AIR_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.preprocessed.clone())
    }
}

impl BaseAirWithPublicValues<KoalaBear> for Sha512RoundAir {
    fn num_public_values(&self) -> usize {
        16
    }
}

impl<AB> Air<AB> for Sha512RoundAir
where
    AB: AirBuilderWithPublicValues<F = KoalaBear> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let local = main.row_slice(0).expect("window has local row");
        let next = main.row_slice(1).expect("window has next row");
        let local_prep = prep
            .row_slice(0)
            .expect("window has local preprocessed row");

        for limb in 0..LIMBS_PER_WORD {
            // Bind K exactly as a 64-bit value, not just modulo the base field.
            builder.assert_zero(
                local_prep[PREP_ROUND_SELECTOR_COL].clone()
                    * (local[limb_col(WORD_K, limb)].clone()
                        - local_prep[limb_col(WORD_K, limb)].clone()),
            );
        }
        for limb in 0..LIMBS_PER_WORD {
            // Bind W[0..15] exactly as 64-bit words from the instance.
            builder.assert_zero(
                local_prep[PREP_FIXED_INIT_W_SELECTOR_COL].clone()
                    * (local[limb_col(WORD_W, limb)].clone()
                        - local_prep[limb_col(WORD_W, limb)].clone()),
            );
        }
        for (word_idx, row_sel) in [
            (0_usize, local_prep[PREP_PAYLOAD_WORD0_SELECTOR_COL].clone()),
            (1_usize, local_prep[PREP_PAYLOAD_WORD1_SELECTOR_COL].clone()),
            (2_usize, local_prep[PREP_PAYLOAD_WORD2_SELECTOR_COL].clone()),
            (3_usize, local_prep[PREP_PAYLOAD_WORD3_SELECTOR_COL].clone()),
        ] {
            let seed_or_sk_sel = local_prep[PREP_SEGMENT_HASH_SELECTOR_COL].clone();
            for limb in 0..LIMBS_PER_WORD {
                let seed_limb = local[private_seed_limb_col(word_idx, limb)].clone();
                let sk_limb = local[private_sk_limb_col(word_idx, limb)].clone();
                let expected = seed_limb.clone() * (AB::Expr::ONE - seed_or_sk_sel.clone())
                    + sk_limb.clone() * seed_or_sk_sel.clone();
                builder.assert_zero(
                    row_sel.clone() * (local[limb_col(WORD_W, limb)].clone() - expected),
                );
            }
        }
        for limb in 0..LIMBS_PER_WORD {
            builder.assert_zero(
                (AB::Expr::ONE - local_prep[PREP_ROUND_SELECTOR_COL].clone())
                    * local[limb_col(WORD_W, limb)].clone(),
            );
        }
        constrain_private_sk_from_derive_final(
            builder,
            &local,
            &local_prep,
            local_prep[PREP_DERIVE_FINAL_SELECTOR_COL].clone().into(),
        );

        let block_start_sel = local_prep[PREP_BLOCK_START_SELECTOR_COL].clone();
        for word in WORD_A..=WORD_H {
            for limb in 0..LIMBS_PER_WORD {
                builder.assert_zero(
                    block_start_sel.clone()
                        * (local[limb_col(word, limb)].clone()
                            - local_prep[limb_col(word, limb)].clone()),
                );
            }
        }

        let public: [AB::PublicVar; 16] = core::array::from_fn(|i| builder.public_values()[i]);
        let generic_final_sel = local_prep[PREP_FINAL_SELECTOR_COL].clone()
            * (AB::Expr::ONE
                - local_prep[PREP_SEGMENT_COMMIT_SELECTOR_COL].clone()
                - local_prep[PREP_SEGMENT_DERIVE_SELECTOR_COL].clone()
                - local_prep[PREP_SEGMENT_HASH_SELECTOR_COL].clone());
        let commit_final_sel = local_prep[PREP_COMMIT_FINAL_SELECTOR_COL].clone();
        let hash_final_sel = local_prep[PREP_HASH_FINAL_SELECTOR_COL].clone();
        for i in 0..8 {
            builder.assert_zero(
                (generic_final_sel.clone() + commit_final_sel.clone())
                    * (public[i].into() - pack_word_from_limbs::<AB>(&local, i)),
            );
            builder.assert_zero(
                hash_final_sel.clone()
                    * (public[8 + i].into() - pack_word_from_limbs::<AB>(&local, i)),
            );
        }
        let round_sel = local_prep[PREP_ROUND_SELECTOR_COL].clone();

        for (word, base) in [
            (WORD_A, BIT_A_BASE),
            (WORD_B, BIT_B_BASE),
            (WORD_C, BIT_C_BASE),
            (WORD_E, BIT_E_BASE),
            (WORD_F, BIT_F_BASE),
            (WORD_G, BIT_G_BASE),
        ] {
            for bit in 0..64 {
                builder.assert_zero(
                    round_sel.clone()
                        * (local[base + bit].clone() * (AB::Expr::ONE - local[base + bit].clone())),
                );
            }
            builder.assert_zero(
                round_sel.clone()
                    * (pack_word_from_limbs::<AB>(&local, word) - pack_bits::<AB>(&local, base)),
            );
            for limb in 0..LIMBS_PER_WORD {
                let mut limb_expr = AB::Expr::ZERO;
                for bit in 0..16 {
                    let bit_col = base + limb * 16 + bit;
                    limb_expr += local[bit_col].clone() * KoalaBear::from_u32(1 << bit);
                }
                builder.assert_zero(
                    round_sel.clone() * (local[limb_col(word, limb)].clone() - limb_expr),
                );
            }
        }
        for limb in 0..LIMBS_PER_WORD {
            let mut sigma0_limb = AB::Expr::ZERO;
            let mut sigma1_limb = AB::Expr::ZERO;
            let mut ch_limb = AB::Expr::ZERO;
            let mut maj_limb = AB::Expr::ZERO;
            for bit in 0..16 {
                let bit_idx = limb * 16 + bit;
                let a = local[BIT_A_BASE + bit_idx].clone();
                let b = local[BIT_B_BASE + bit_idx].clone();
                let c = local[BIT_C_BASE + bit_idx].clone();
                let e = local[BIT_E_BASE + bit_idx].clone();
                let f = local[BIT_F_BASE + bit_idx].clone();
                let g = local[BIT_G_BASE + bit_idx].clone();

                let sigma0 = xor3_expr::<AB>(
                    local[BIT_A_BASE + ((bit_idx + 28) % 64)].clone().into(),
                    local[BIT_A_BASE + ((bit_idx + 34) % 64)].clone().into(),
                    local[BIT_A_BASE + ((bit_idx + 39) % 64)].clone().into(),
                );
                let sigma1 = xor3_expr::<AB>(
                    local[BIT_E_BASE + ((bit_idx + 14) % 64)].clone().into(),
                    local[BIT_E_BASE + ((bit_idx + 18) % 64)].clone().into(),
                    local[BIT_E_BASE + ((bit_idx + 41) % 64)].clone().into(),
                );
                let ch_expr = e.clone() * f.clone() + (AB::Expr::ONE - e) * g.clone();
                let ab = a.clone() * b.clone();
                let ac = a.clone() * c.clone();
                let bc = b.clone() * c.clone();
                let abc = a * b * c;
                let maj_expr = ab + ac + bc - abc * KoalaBear::TWO;
                let bit_weight = KoalaBear::from_u32(1 << bit);
                sigma0_limb += sigma0 * bit_weight;
                sigma1_limb += sigma1 * bit_weight;
                ch_limb += ch_expr * bit_weight;
                maj_limb += maj_expr * bit_weight;
            }
            builder.assert_zero(
                round_sel.clone() * (local[limb_col(WORD_SIGMA0, limb)].clone() - sigma0_limb),
            );
            builder.assert_zero(
                round_sel.clone() * (local[limb_col(WORD_SIGMA1, limb)].clone() - sigma1_limb),
            );
            builder.assert_zero(
                round_sel.clone() * (local[limb_col(WORD_CH, limb)].clone() - ch_limb),
            );
            builder.assert_zero(
                round_sel.clone() * (local[limb_col(WORD_MAJ, limb)].clone() - maj_limb),
            );
        }

        for src in 0..RANGE_SOURCES {
            let mut packed = AB::Expr::ZERO;
            for bit in 0..RANGE_BITS_PER_SOURCE {
                let b = local[range_bit_col(src, bit)].clone();
                builder.assert_bool(b.clone());
                packed += b * KoalaBear::from_u32(1 << bit);
            }
            builder.assert_eq(local[range_source_col(src)].clone(), packed);
        }

        for (lag, base) in [(1_usize, LAG1_BIT_BASE), (14_usize, LAG14_BIT_BASE)] {
            for bit in 0..64 {
                builder.assert_bool(local[base + bit].clone());
            }
            for limb in 0..LIMBS_PER_WORD {
                let mut packed = AB::Expr::ZERO;
                for bit in 0..16 {
                    packed += local[base + limb * 16 + bit].clone() * KoalaBear::from_u32(1 << bit);
                }
                builder.assert_eq(local[lag_limb_col(lag, limb)].clone(), packed);
            }
        }

        let mut global_transition = builder.when_transition();
        for word in 0..4 {
            for limb in 0..LIMBS_PER_WORD {
                global_transition.assert_eq(
                    next[private_seed_limb_col(word, limb)].clone(),
                    local[private_seed_limb_col(word, limb)].clone(),
                );
                global_transition.assert_eq(
                    next[private_sk_limb_col(word, limb)].clone(),
                    local[private_sk_limb_col(word, limb)].clone(),
                );
            }
        }

        let mut transition_window = builder.when_transition();
        let mut transition =
            transition_window.when(local_prep[PREP_TRANSITION_SELECTOR_COL].clone());
        constrain_add_5_limbs(
            &mut transition,
            &local,
            [WORD_H, WORD_SIGMA1, WORD_CH, WORD_K, WORD_W],
            WORD_T1,
            CARRY_T1_BASE,
        );
        constrain_add_2_limbs(
            &mut transition,
            &local,
            WORD_SIGMA0,
            WORD_MAJ,
            WORD_T2,
            CARRY_T2_BASE,
        );
        constrain_add_2_limbs_across_rows(
            &mut transition,
            &local,
            &next,
            WORD_T1,
            WORD_T2,
            WORD_A,
            CARRY_A_BASE,
        );
        constrain_add_2_limbs_across_rows(
            &mut transition,
            &local,
            &next,
            WORD_D,
            WORD_T1,
            WORD_E,
            CARRY_E_BASE,
        );

        for limb in 0..LIMBS_PER_WORD {
            transition.assert_eq(
                next[limb_col(WORD_B, limb)].clone(),
                local[limb_col(WORD_A, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_C, limb)].clone(),
                local[limb_col(WORD_B, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_D, limb)].clone(),
                local[limb_col(WORD_C, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_F, limb)].clone(),
                local[limb_col(WORD_E, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_G, limb)].clone(),
                local[limb_col(WORD_F, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_H, limb)].clone(),
                local[limb_col(WORD_G, limb)].clone(),
            );
        }

        for lag in 0..LAG_COUNT {
            for limb in 0..LIMBS_PER_WORD {
                let expected = if lag == 0 {
                    local[limb_col(WORD_W, limb)].clone()
                } else {
                    local[lag_limb_col(lag - 1, limb)].clone()
                };
                transition.assert_eq(next[lag_limb_col(lag, limb)].clone(), expected);
            }
        }
        let sched_sel = local_prep[PREP_ROUND_SELECTOR_COL].clone()
            * (AB::Expr::ONE - local_prep[PREP_FIXED_INIT_W_SELECTOR_COL].clone())
            * (AB::Expr::ONE - local_prep[PREP_PAYLOAD_WORD_SELECTOR_COL].clone());
        constrain_schedule_recurrence(&mut transition, &local, sched_sel);

        let mut last = builder.when_last_row();
        for word in WORD_W..WORD_COUNT {
            for limb in 0..LIMBS_PER_WORD {
                last.assert_eq(local[limb_col(word, limb)].clone(), KoalaBear::ZERO);
            }
        }
        for col in CARRY_T1_BASE..BIT_A_BASE {
            last.assert_eq(local[col].clone(), KoalaBear::ZERO);
        }
    }
}

fn pack_word_from_limbs<AB: AirBuilder<F = KoalaBear>>(row: &[AB::Var], word: usize) -> AB::Expr {
    let two16 = KoalaBear::from_u32(1 << 16);
    let two32 = KoalaBear::from_u64(1_u64 << 32);
    let two48 = KoalaBear::from_u64(1_u64 << 48);
    row[limb_col(word, 0)].clone()
        + row[limb_col(word, 1)].clone() * two16
        + row[limb_col(word, 2)].clone() * two32
        + row[limb_col(word, 3)].clone() * two48
}

impl Sha512Circuit {
    /// Builds the instance-specific preprocessed trace matrix.
    ///
    /// The preprocessed trace has the same dimensions as the main trace
    /// (128 rows × `AIR_WIDTH` columns) but only a small subset of columns are
    /// populated.  All other cells are zero.  Populated columns:
    ///
    /// * `limb_col(WORD_K, ..)`      — round constant K\[i\] limbs in rows 0..80; zero in rows 80..127.
    /// * `limb_col(WORD_W, ..)`      — W\[i\] limbs in rows 0..15 (bound by `PREP_INIT_W_SELECTOR_COL`).
    /// * `limb_col(WORD_A..WORD_H, ..)` — initial state limbs, constant across all rows;
    ///   the first-row boundary constraint uses these to bind the main trace.
    /// * `PREP_ROUND_SELECTOR_COL`   — 1 in rows 0..79, 0 elsewhere.
    /// * `PREP_INIT_W_SELECTOR_COL`  — 1 in rows 0..15, 0 elsewhere.
    /// * `PREP_BLOCK_START_SELECTOR_COL` — 1 on row 0 (block start), 0 elsewhere.
    /// * `PREP_TRANSITION_SELECTOR_COL`  — 1 in rows 0..126, 0 on row 127.
    /// * `PREP_FINAL_SELECTOR_COL`   — 1 in row 80 only.
    ///
    /// # Panics
    ///
    /// Panics internally if `compress_block` or `build_plonky3_air_trace` fails
    /// (should not occur for valid inputs).
    pub fn build_plonky3_preprocessed_trace_from_instance(
        initial_state: &[u64; 8],
        block: &[u8; 128],
    ) -> RowMajorMatrix<KoalaBear> {
        let trace = Sha512Circuit::compress_block(initial_state, block);
        let full = Sha512Circuit::build_plonky3_air_trace(&trace);
        let mut values = vec![KoalaBear::ZERO; TRACE_ROWS * AIR_WIDTH];

        for row in 0..TRACE_ROWS {
            let src = full.row_slice(row).expect("row exists");
            let dst = &mut values[row * AIR_WIDTH..(row + 1) * AIR_WIDTH];
            for limb in 0..LIMBS_PER_WORD {
                dst[limb_col(WORD_W, limb)] = src[limb_col(WORD_W, limb)];
                dst[limb_col(WORD_K, limb)] = src[limb_col(WORD_K, limb)];
            }
            dst[PREP_ROUND_SELECTOR_COL] = KoalaBear::from_bool(row < 80);
            dst[PREP_INIT_W_SELECTOR_COL] = KoalaBear::from_bool(row < 16);
            dst[PREP_FIXED_INIT_W_SELECTOR_COL] = KoalaBear::from_bool(row < 16);
            dst[PREP_BLOCK_START_SELECTOR_COL] = KoalaBear::from_bool(row == 0);
            dst[PREP_TRANSITION_SELECTOR_COL] = KoalaBear::from_bool(row + 1 < TRACE_ROWS);
            dst[PREP_FINAL_SELECTOR_COL] = KoalaBear::from_bool(row == 80);
            for (offset, value) in initial_state.iter().copied().enumerate() {
                let word = WORD_A + offset;
                for limb in 0..LIMBS_PER_WORD {
                    let limb_value = ((value >> (16 * limb)) & 0xffff) as u16;
                    dst[limb_col(word, limb)] = KoalaBear::from_u16(limb_value);
                }
            }
        }

        RowMajorMatrix::new(values, AIR_WIDTH)
    }

    /// Builds the full AIR witness (main trace) from a [`BlockTrace`].
    ///
    /// Produces a 128-row × `AIR_WIDTH`-column [`RowMajorMatrix`] in KoalaBear.
    ///
    /// ## Row structure
    ///
    /// * **Rows 0–79** (round rows): For each SHA-512 round `i`, fills in the
    ///   16-bit limb decompositions for all tracked words (a..h, W, K, Σ0, Σ1, Ch, Maj, T1, T2),
    ///   carry values for each limb-wise addition (T1, T2, A, E,
    ///   and schedule), 64-bit Boolean decompositions for bitwise operations, and the
    ///   corresponding range-proof bit columns.
    ///
    /// * **Row 80** (final state row): Contains only the 8 working-state limbs
    ///   (`round_states[80]`) together with the lag history
    ///   for the schedule, and degenerate "padding helpers" (W = K = 0, all carry /
    ///   bit columns zeroed).  This row's words are bound to the 8 public values by
    ///   the `PREP_FINAL_SELECTOR_COL` constraint.
    ///
    /// * **Rows 81–127** (padding rows): Degenerate rows that extend the trace to
    ///   the required power-of-two length (128).  The register-shift transition
    ///   constraints still hold here (b ← a, etc.), but W = K = 0 and all non-state
    ///   helper columns are zero.
    ///
    /// ## Column groups
    ///
    /// | Group | Column range | Purpose |
    /// |-------|-------------|---------|
    /// | Limbs | 0–63 | 4 × 16-bit decomposition per word |
    /// | Carries | 64–79 | Per-limb carries for T1, T2, A, E additions |
    /// | Lag limbs | 80–143 | Previous 16 W values, 4 limbs each |
    /// | Sched carries | 144–147 | Carries for the W recurrence |
    /// | Bits | 148–531 | 64-bit Boolean decompositions for a,b,c,e,f,g |
    /// | Lag sigma bits | 532–659 | 64-bit decomposition for lag1 and lag14 |
    /// | Range bits | 660–1043 | 16-bit range proofs for D/H/W/K/T1/T2 limbs |
    /// | Carry bits | 1044–1075 | Minimal-width carry bit decompositions |
    pub fn build_plonky3_air_trace(trace: &BlockTrace) -> RowMajorMatrix<KoalaBear> {
        let mut values = Vec::with_capacity(TRACE_ROWS * AIR_WIDTH);
        let mut lags = [0_u64; LAG_COUNT];

        for (i, &constant) in K.iter().enumerate() {
            let s = trace.round_states[i];
            let word = trace.words[i];
            let sigma0 = big_sigma0(s[0]);
            let sigma1 = big_sigma1(s[4]);
            let choose = ch(s[4], s[5], s[6]);
            let majority = maj(s[0], s[1], s[2]);
            let t1 = s[7]
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let t2 = sigma0.wrapping_add(majority);

            let (_, carry_t1) = add_with_carries_5(s[7], sigma1, choose, constant, word);
            let (_, carry_t2) = add_with_carries_2(sigma0, majority);
            let (_, carry_a) = add_with_carries_2(t1, t2);
            let (_, carry_e) = add_with_carries_2(s[3], t1);
            let sched_carries = if i >= 16 {
                let w2 = trace.words[i - 2];
                let w7 = trace.words[i - 7];
                let w15 = trace.words[i - 15];
                let w16 = trace.words[i - 16];
                let (_, carries) = add_with_carries_4(small_sigma1(w2), w7, small_sigma0(w15), w16);
                carries
            } else {
                [0; LIMBS_PER_WORD]
            };

            let mut row = [KoalaBear::ZERO; AIR_WIDTH];
            let words = [
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], word, constant, sigma0, sigma1,
                choose, majority, t1, t2,
            ];
            for (w, &value) in words.iter().enumerate() {
                set_word_limbs(&mut row, w, value);
            }
            set_lag_words(&mut row, &lags);
            set_lag_sigma_bits(&mut row, &lags);
            set_helper_bits(&mut row);
            set_carries(&mut row, CARRY_T1_BASE, carry_t1);
            set_carries(&mut row, CARRY_T2_BASE, carry_t2);
            set_carries(&mut row, CARRY_A_BASE, carry_a);
            set_carries(&mut row, CARRY_E_BASE, carry_e);
            set_carries(&mut row, SCHED_CARRY_BASE, sched_carries);
            set_carry_bits(&mut row);
            set_range_bits(&mut row);

            values.extend(row);
            advance_lags(&mut lags, word);
        }

        let mut row80 = [KoalaBear::ZERO; AIR_WIDTH];
        let s = trace.round_states[80];
        let words = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        for (w, &value) in words.iter().enumerate() {
            set_word_limbs(&mut row80, w, value);
        }
        set_lag_words(&mut row80, &lags);
        set_lag_sigma_bits(&mut row80, &lags);
        set_helper_bits(&mut row80);
        seed_padding_helpers(&mut row80);
        set_carry_bits(&mut row80);
        set_range_bits(&mut row80);
        values.extend(row80);
        advance_lags(&mut lags, 0);

        let mut state = trace.round_states[80];
        for row_idx in SHA_ROUNDS_PLUS_INIT..TRACE_ROWS {
            let next_state = [
                state[7],
                state[0],
                state[1],
                state[2],
                state[3].wrapping_add(state[7]),
                state[4],
                state[5],
                state[6],
            ];

            let mut row = [KoalaBear::ZERO; AIR_WIDTH];
            let words = [
                next_state[0],
                next_state[1],
                next_state[2],
                next_state[3],
                next_state[4],
                next_state[5],
                next_state[6],
                next_state[7],
            ];
            for (w, &value) in words.iter().enumerate() {
                set_word_limbs(&mut row, w, value);
            }
            set_lag_words(&mut row, &lags);
            set_lag_sigma_bits(&mut row, &lags);
            set_helper_bits(&mut row);
            if row_idx != TRACE_ROWS - 1 {
                seed_padding_helpers(&mut row);
            }
            set_carry_bits(&mut row);
            set_range_bits(&mut row);
            values.extend(row);
            advance_lags(&mut lags, 0);
            state = next_state;
        }

        RowMajorMatrix::new(values, AIR_WIDTH)
    }

    pub(crate) fn build_private_seed_chain_air_bundle(
        blocks: &PrivateSeedChainBlocks,
    ) -> MessageAirBundle {
        seed_chain::build_private_seed_chain_air_bundle(blocks)
    }
}

pub(crate) struct MessageAirBundle {
    pub(crate) main: RowMajorMatrix<KoalaBear>,
    pub(crate) preprocessed: RowMajorMatrix<KoalaBear>,
    pub(crate) final_state: [u64; 8],
    pub(crate) final_public_values: [KoalaBear; 16],
    pub(crate) degree_bits: usize,
}

#[cfg(test)]
pub(crate) use columns::{
    LIMB_BASE_FOR_TESTS, LIMBS_PER_WORD_FOR_TESTS, PREP_COMMIT_FINAL_SELECTOR_COL_FOR_TESTS,
    PREP_DERIVE_FINAL_SELECTOR_COL_FOR_TESTS, PREP_FIXED_INIT_W_SELECTOR_COL_FOR_TESTS,
    PREP_HASH_FINAL_SELECTOR_COL_FOR_TESTS, PREP_PAYLOAD_WORD_SELECTOR_COL_FOR_TESTS,
    PREP_SEGMENT_COMMIT_SELECTOR_COL_FOR_TESTS, PREP_SEGMENT_DERIVE_SELECTOR_COL_FOR_TESTS,
    PREP_SEGMENT_HASH_SELECTOR_COL_FOR_TESTS, PRIVATE_SEED_LIMB_BASE_FOR_TESTS,
    PRIVATE_SK_LIMB_BASE_FOR_TESTS, WORD_W_FOR_TESTS,
};
