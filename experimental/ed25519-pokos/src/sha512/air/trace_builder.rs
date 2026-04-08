use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;

use super::columns::{
    AIR_WIDTH, BIT_A_BASE, BIT_B_BASE, BIT_C_BASE, BIT_E_BASE, BIT_F_BASE, BIT_G_BASE,
    CARRY_A_BASE, CARRY_E_BASE, CARRY_T1_BASE, CARRY_T2_BASE, LAG_COUNT, LAG_LIMB_BASE,
    LIMBS_PER_WORD, RANGE_BITS_PER_SOURCE, RANGE_SOURCES, SCHED_CARRY_BASE, WORD_A, WORD_B, WORD_C,
    WORD_CH, WORD_E, WORD_F, WORD_G, WORD_K, WORD_MAJ, WORD_SIGMA0, WORD_SIGMA1, WORD_T1, WORD_T2,
    WORD_W, carry_bit_col, carry_bit_width, lag_limb_col, limb_col, private_seed_limb_col,
    private_sk_limb_col, range_bit_col, range_source_col,
};
use super::columns::{LAG1_BIT_BASE, LAG14_BIT_BASE};

pub(super) fn set_word_limbs(row: &mut [KoalaBear; AIR_WIDTH], word: usize, value: u64) {
    let limbs = u64_to_limbs(value);
    for (i, limb) in limbs.into_iter().enumerate() {
        row[limb_col(word, i)] = KoalaBear::from_u16(limb);
    }
}

pub(super) fn set_lag_words(row: &mut [KoalaBear; AIR_WIDTH], lags: &[u64; LAG_COUNT]) {
    for (lag, value) in lags.iter().copied().enumerate() {
        let limbs = u64_to_limbs(value);
        for (limb, limb_value) in limbs.into_iter().enumerate() {
            row[lag_limb_col(lag, limb)] = KoalaBear::from_u16(limb_value);
        }
    }
}

pub(super) fn set_carries(
    row: &mut [KoalaBear; AIR_WIDTH],
    base: usize,
    carries: [u16; LIMBS_PER_WORD],
) {
    for (i, carry) in carries.into_iter().enumerate() {
        row[base + i] = KoalaBear::from_u16(carry);
    }
}

pub(super) fn set_range_bits(row: &mut [KoalaBear; AIR_WIDTH]) {
    for source in 0..RANGE_SOURCES {
        let value_col = range_source_col(source);
        let x = row[value_col].as_canonical_u32();
        for bit in 0..RANGE_BITS_PER_SOURCE {
            row[range_bit_col(source, bit)] = KoalaBear::from_bool(((x >> bit) & 1) == 1);
        }
    }
}

pub(super) fn set_carry_bits(row: &mut [KoalaBear; AIR_WIDTH]) {
    for carry_col in CARRY_T1_BASE..LAG_LIMB_BASE {
        let width = carry_bit_width(carry_col);
        let x = row[carry_col].as_canonical_u32();
        for bit in 0..width {
            row[carry_bit_col(carry_col, bit)] = KoalaBear::from_bool(((x >> bit) & 1) == 1);
        }
    }
    for carry_col in SCHED_CARRY_BASE..BIT_A_BASE {
        let width = carry_bit_width(carry_col);
        let x = row[carry_col].as_canonical_u32();
        for bit in 0..width {
            row[carry_bit_col(carry_col, bit)] = KoalaBear::from_bool(((x >> bit) & 1) == 1);
        }
    }
}

pub(super) fn advance_lags(lags: &mut [u64; LAG_COUNT], word: u64) {
    for i in (1..LAG_COUNT).rev() {
        lags[i] = lags[i - 1];
    }
    lags[0] = word;
}

pub(super) fn seed_padding_helpers(row: &mut [KoalaBear; AIR_WIDTH]) {
    let h = decode_word_from_inline(row, 7);
    let d = decode_word_from_inline(row, 3);

    let t1 = h;
    let t2 = 0_u64;
    let (_, carry_t1) = add_with_carries_5(h, 0, 0, 0, 0);
    let (_, carry_t2) = add_with_carries_2(0, 0);
    let (_, carry_a) = add_with_carries_2(t1, t2);
    let (_, carry_e) = add_with_carries_2(d, t1);

    set_word_limbs(row, WORD_W, 0);
    set_word_limbs(row, WORD_K, 0);
    set_word_limbs(row, WORD_SIGMA0, 0);
    set_word_limbs(row, WORD_SIGMA1, 0);
    set_word_limbs(row, WORD_CH, 0);
    set_word_limbs(row, WORD_MAJ, 0);
    set_word_limbs(row, WORD_T1, t1);
    set_word_limbs(row, WORD_T2, 0);
    set_helper_bits(row);

    set_carries(row, CARRY_T1_BASE, carry_t1);
    set_carries(row, CARRY_T2_BASE, carry_t2);
    set_carries(row, CARRY_A_BASE, carry_a);
    set_carries(row, CARRY_E_BASE, carry_e);
    set_carries(row, SCHED_CARRY_BASE, [0; LIMBS_PER_WORD]);
}

pub(super) fn set_helper_bits(row: &mut [KoalaBear; AIR_WIDTH]) {
    for (word, base) in [
        (WORD_A, BIT_A_BASE),
        (WORD_B, BIT_B_BASE),
        (WORD_C, BIT_C_BASE),
        (WORD_E, BIT_E_BASE),
        (WORD_F, BIT_F_BASE),
        (WORD_G, BIT_G_BASE),
    ] {
        let value = decode_word_from_inline(row, word);
        for i in 0..64 {
            row[base + i] = KoalaBear::from_bool(((value >> i) & 1) == 1);
        }
    }
}

pub(super) fn set_lag_sigma_bits(row: &mut [KoalaBear; AIR_WIDTH], lags: &[u64; LAG_COUNT]) {
    for i in 0..64 {
        row[LAG1_BIT_BASE + i] = KoalaBear::from_bool(((lags[1] >> i) & 1) == 1);
        row[LAG14_BIT_BASE + i] = KoalaBear::from_bool(((lags[14] >> i) & 1) == 1);
    }
}

pub(super) fn set_private_seed_chain_words(
    row: &mut [KoalaBear; AIR_WIDTH],
    seed_words: [u64; 4],
    sk_words: [u64; 4],
) {
    for word in 0..4 {
        let seed_limbs = u64_to_limbs(seed_words[word]);
        let sk_limbs = u64_to_limbs(sk_words[word]);
        for limb in 0..LIMBS_PER_WORD {
            row[private_seed_limb_col(word, limb)] = KoalaBear::from_u16(seed_limbs[limb]);
            row[private_sk_limb_col(word, limb)] = KoalaBear::from_u16(sk_limbs[limb]);
        }
    }
}

pub(super) fn set_private_seed_chain_derive_final_carries(
    row: &mut [KoalaBear; AIR_WIDTH],
    derive_round_state: [u64; 8],
    initial_state: [u64; 8],
) {
    for (word_idx, carry_base) in [
        (0_usize, CARRY_T1_BASE),
        (1_usize, CARRY_T2_BASE),
        (2_usize, CARRY_A_BASE),
        (3_usize, CARRY_E_BASE),
    ] {
        let (_, carries) =
            add_with_carries_2(derive_round_state[word_idx], initial_state[word_idx]);
        set_carries(row, carry_base, carries);
    }
    set_carry_bits(row);
}

fn u64_to_limbs(value: u64) -> [u16; LIMBS_PER_WORD] {
    [
        (value & 0xffff) as u16,
        ((value >> 16) & 0xffff) as u16,
        ((value >> 32) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
    ]
}

fn decode_word_from_inline(row: &[KoalaBear; AIR_WIDTH], word: usize) -> u64 {
    let mut out = 0_u64;
    for limb in 0..LIMBS_PER_WORD {
        let x = row[limb_col(word, limb)].as_canonical_u32();
        out |= u64::from(x) << (16 * limb);
    }
    out
}

pub(super) fn add_with_carries_2(a: u64, b: u64) -> (u64, [u16; LIMBS_PER_WORD]) {
    add_with_carries(&[u64_to_limbs(a), u64_to_limbs(b)])
}

pub(super) fn add_with_carries_4(a: u64, b: u64, c: u64, d: u64) -> (u64, [u16; LIMBS_PER_WORD]) {
    add_with_carries(&[
        u64_to_limbs(a),
        u64_to_limbs(b),
        u64_to_limbs(c),
        u64_to_limbs(d),
    ])
}

pub(super) fn add_with_carries_5(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
) -> (u64, [u16; LIMBS_PER_WORD]) {
    add_with_carries(&[
        u64_to_limbs(a),
        u64_to_limbs(b),
        u64_to_limbs(c),
        u64_to_limbs(d),
        u64_to_limbs(e),
    ])
}

/// Limb-wise addition of `operands` with carry propagation.
///
/// Returns `(sum mod 2^64, per-limb carries)`.  Each carry is the value carried
/// into the next 16-bit limb after summing all operand limbs at that position.
fn add_with_carries(operands: &[[u16; LIMBS_PER_WORD]]) -> (u64, [u16; LIMBS_PER_WORD]) {
    let mut out = [0_u16; LIMBS_PER_WORD];
    let mut carries = [0_u16; LIMBS_PER_WORD];
    let mut carry = 0_u32;

    for i in 0..LIMBS_PER_WORD {
        let sum: u32 = operands.iter().map(|o| u32::from(o[i])).sum::<u32>() + carry;
        out[i] = (sum & 0xffff) as u16;
        carry = sum >> 16;
        carries[i] = carry as u16;
    }

    (limbs_to_u64(out), carries)
}

fn limbs_to_u64(limbs: [u16; LIMBS_PER_WORD]) -> u64 {
    u64::from(limbs[0])
        | (u64::from(limbs[1]) << 16)
        | (u64::from(limbs[2]) << 32)
        | (u64::from(limbs[3]) << 48)
}
