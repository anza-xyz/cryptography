use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    AIR_WIDTH, INITIAL_STATE, LIMBS_PER_WORD, MessageAirBundle, PREP_BLOCK_START_SELECTOR_COL,
    PREP_COMMIT_FINAL_SELECTOR_COL, PREP_DERIVE_FINAL_SELECTOR_COL, PREP_FINAL_SELECTOR_COL,
    PREP_FIXED_INIT_W_SELECTOR_COL, PREP_HASH_FINAL_SELECTOR_COL, PREP_INIT_W_SELECTOR_COL,
    PREP_PAYLOAD_WORD_SELECTOR_COL, PREP_PAYLOAD_WORD0_SELECTOR_COL,
    PREP_PAYLOAD_WORD1_SELECTOR_COL, PREP_PAYLOAD_WORD2_SELECTOR_COL,
    PREP_PAYLOAD_WORD3_SELECTOR_COL, PREP_ROUND_SELECTOR_COL, PREP_SEGMENT_COMMIT_SELECTOR_COL,
    PREP_SEGMENT_DERIVE_SELECTOR_COL, PREP_SEGMENT_HASH_SELECTOR_COL, PREP_TRANSITION_SELECTOR_COL,
    PrivateSeedChainBlocks, SHA_ROUNDS_PLUS_INIT, Sha512Circuit, TRACE_ROWS, WORD_A, WORD_K,
    WORD_W, bb, limb_col, set_private_seed_chain_derive_final_carries,
    set_private_seed_chain_words,
};

pub(super) fn build_private_seed_chain_air_bundle(
    blocks: &PrivateSeedChainBlocks,
) -> MessageAirBundle {
    let payload_words = |block: [u8; 128]| -> [u64; 4] {
        core::array::from_fn(|i| {
            let start = 32 + i * 8;
            u64::from_be_bytes(block[start..start + 8].try_into().expect("payload word"))
        })
    };
    let seed_words = payload_words(blocks.commit);
    let sk_words = payload_words(blocks.hash_sk);
    let segments = [
        (INITIAL_STATE, blocks.commit),
        (INITIAL_STATE, blocks.derive),
        (INITIAL_STATE, blocks.hash_sk),
    ];
    let real_segment_count = segments.len();
    let segment_count = real_segment_count.next_power_of_two().max(1);
    let total_rows = segment_count * TRACE_ROWS;
    let degree_bits = total_rows.trailing_zeros() as usize;
    debug_assert_eq!(1_usize << degree_bits, total_rows);

    let mut main_values = vec![KoalaBear::ZERO; total_rows * AIR_WIDTH];
    let mut prep_values = vec![KoalaBear::ZERO; total_rows * AIR_WIDTH];

    #[cfg(test)]
    let mut final_state = [0_u64; 8];
    let mut final_public_values = [KoalaBear::ZERO; 16];

    for row in 0..total_rows {
        let dst_base = row * AIR_WIDTH;
        let row_slice: &mut [KoalaBear] = &mut main_values[dst_base..dst_base + AIR_WIDTH];
        let row_array: &mut [KoalaBear; AIR_WIDTH] = row_slice.try_into().expect("row width");
        set_private_seed_chain_words(row_array, seed_words, sk_words);
    }

    for (seg, (state, block)) in segments.iter().copied().enumerate() {
        let trace = Sha512Circuit::compress_block(&state, &block);
        let main = Sha512Circuit::build_plonky3_air_trace(&trace);
        let prep = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, &block);

        for row in 0..TRACE_ROWS {
            let dst_base = (seg * TRACE_ROWS + row) * AIR_WIDTH;
            let src_main = main.row_slice(row).expect("main row exists");
            let src_prep = prep.row_slice(row).expect("prep row exists");
            main_values[dst_base..dst_base + AIR_WIDTH].copy_from_slice(&src_main);

            let row_slice: &mut [KoalaBear] = &mut main_values[dst_base..dst_base + AIR_WIDTH];
            let row_array: &mut [KoalaBear; AIR_WIDTH] = row_slice.try_into().expect("row width");
            set_private_seed_chain_words(row_array, seed_words, sk_words);

            for word in WORD_A..WORD_A + 8 {
                for limb in 0..LIMBS_PER_WORD {
                    prep_values[dst_base + limb_col(word, limb)] = src_prep[limb_col(word, limb)];
                }
            }
            for limb in 0..LIMBS_PER_WORD {
                prep_values[dst_base + limb_col(WORD_K, limb)] = src_prep[limb_col(WORD_K, limb)];
            }
            if row < 16 && !(4..8).contains(&row) {
                for limb in 0..LIMBS_PER_WORD {
                    prep_values[dst_base + limb_col(WORD_W, limb)] =
                        src_prep[limb_col(WORD_W, limb)];
                }
            }

            prep_values[dst_base + PREP_BLOCK_START_SELECTOR_COL] = KoalaBear::from_bool(row == 0);
            prep_values[dst_base + PREP_TRANSITION_SELECTOR_COL] =
                KoalaBear::from_bool(row + 1 < TRACE_ROWS && row != 80);
            prep_values[dst_base + PREP_ROUND_SELECTOR_COL] = KoalaBear::from_bool(row < 80);
            prep_values[dst_base + PREP_FINAL_SELECTOR_COL] =
                KoalaBear::from_bool(seg + 1 == real_segment_count && row == 80);

            prep_values[dst_base + PREP_SEGMENT_COMMIT_SELECTOR_COL] =
                KoalaBear::from_bool(seg == 0);
            prep_values[dst_base + PREP_SEGMENT_DERIVE_SELECTOR_COL] =
                KoalaBear::from_bool(seg == 1);
            prep_values[dst_base + PREP_SEGMENT_HASH_SELECTOR_COL] = KoalaBear::from_bool(seg == 2);
            prep_values[dst_base + PREP_COMMIT_FINAL_SELECTOR_COL] =
                KoalaBear::from_bool(seg == 0 && row == 80);
            prep_values[dst_base + PREP_DERIVE_FINAL_SELECTOR_COL] =
                KoalaBear::from_bool(seg == 1 && row == 80);
            prep_values[dst_base + PREP_HASH_FINAL_SELECTOR_COL] =
                KoalaBear::from_bool(seg == 2 && row == 80);

            // Fixed 32-byte-domain || 32-byte-payload layout:
            // rows 4..7 carry the private payload words W[4..7].
            prep_values[dst_base + PREP_INIT_W_SELECTOR_COL] =
                KoalaBear::from_bool(row < 16 && !(4..8).contains(&row));
            prep_values[dst_base + PREP_PAYLOAD_WORD_SELECTOR_COL] =
                KoalaBear::from_bool((4..8).contains(&row));
            prep_values[dst_base + PREP_FIXED_INIT_W_SELECTOR_COL] =
                KoalaBear::from_bool(row < 16 && !(4..8).contains(&row));
            prep_values[dst_base + PREP_PAYLOAD_WORD0_SELECTOR_COL] =
                KoalaBear::from_bool(row == 4);
            prep_values[dst_base + PREP_PAYLOAD_WORD1_SELECTOR_COL] =
                KoalaBear::from_bool(row == 5);
            prep_values[dst_base + PREP_PAYLOAD_WORD2_SELECTOR_COL] =
                KoalaBear::from_bool(row == 6);
            prep_values[dst_base + PREP_PAYLOAD_WORD3_SELECTOR_COL] =
                KoalaBear::from_bool(row == 7);

            if seg == 1 && row == 80 {
                set_private_seed_chain_derive_final_carries(
                    row_array,
                    trace.round_states[80],
                    INITIAL_STATE,
                );
            }
        }

        #[cfg(test)]
        if seg + 1 == real_segment_count {
            final_state = trace.output_state;
        }
        if seg == 0 {
            final_public_values[..8].copy_from_slice(&trace.round_states[80].map(bb));
        }
        if seg == 2 {
            final_public_values[8..].copy_from_slice(&trace.round_states[80].map(bb));
        }
    }

    debug_assert!(total_rows >= SHA_ROUNDS_PLUS_INIT);

    MessageAirBundle {
        main: RowMajorMatrix::new(main_values, AIR_WIDTH),
        preprocessed: RowMajorMatrix::new(prep_values, AIR_WIDTH),
        #[cfg(test)]
        final_state,
        final_public_values,
        degree_bits,
    }
}
