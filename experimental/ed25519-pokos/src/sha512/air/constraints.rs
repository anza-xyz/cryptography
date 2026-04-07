use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use super::columns::{LAG1_BIT_BASE, LAG14_BIT_BASE};
use super::columns::{
    LIMBS_PER_WORD, SCHED_CARRY_BASE, WORD_A, WORD_W, carry_bit_col, carry_bit_width, lag_limb_col,
    limb_col, private_sk_limb_col,
};

pub(super) fn constrain_add_5_limbs<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    ops: [usize; 5],
    out: usize,
    carry_base: usize,
) {
    let two16 = KoalaBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = row[carry_base + limb].clone();
        constrain_carry_max::<AB>(builder, row, carry_base + limb, 4);
        let sum = row[limb_col(ops[0], limb)].clone()
            + row[limb_col(ops[1], limb)].clone()
            + row[limb_col(ops[2], limb)].clone()
            + row[limb_col(ops[3], limb)].clone()
            + row[limb_col(ops[4], limb)].clone()
            + carry_in;
        let rhs = row[limb_col(out, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, rhs);
        carry_in = carry_out.into();
    }
}

pub(super) fn constrain_add_2_limbs<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    lhs: usize,
    rhs: usize,
    out: usize,
    carry_base: usize,
) {
    let two16 = KoalaBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = row[carry_base + limb].clone();
        constrain_carry_max::<AB>(builder, row, carry_base + limb, 1);
        let sum = row[limb_col(lhs, limb)].clone() + row[limb_col(rhs, limb)].clone() + carry_in;
        let expected = row[limb_col(out, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, expected);
        carry_in = carry_out.into();
    }
}

pub(super) fn constrain_add_2_limbs_across_rows<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    lhs: usize,
    rhs: usize,
    out_next: usize,
    carry_base: usize,
) {
    let two16 = KoalaBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = local[carry_base + limb].clone();
        constrain_carry_max::<AB>(builder, local, carry_base + limb, 1);
        let sum =
            local[limb_col(lhs, limb)].clone() + local[limb_col(rhs, limb)].clone() + carry_in;
        let expected = next[limb_col(out_next, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, expected);
        carry_in = carry_out.into();
    }
}

pub(super) fn constrain_schedule_recurrence<B: AirBuilder<F = KoalaBear>>(
    builder: &mut B,
    row: &[B::Var],
    selector: B::Expr,
) {
    let two16 = KoalaBear::from_u32(1 << 16);
    let mut carry_in = B::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let sigma1_limb = pack_small_sigma1_limb::<B>(row, limb);
        let sigma0_limb = pack_small_sigma0_limb::<B>(row, limb);
        let lag7_limb = row[lag_limb_col(6, limb)].clone();
        let lag16_limb = row[lag_limb_col(15, limb)].clone();
        let carry_out = row[SCHED_CARRY_BASE + limb].clone();
        constrain_carry_max::<B>(builder, row, SCHED_CARRY_BASE + limb, 3);

        let sum = sigma1_limb + lag7_limb + sigma0_limb + lag16_limb + carry_in;
        let expected = row[limb_col(WORD_W, limb)].clone() + carry_out.clone() * two16;
        builder.assert_zero(selector.clone() * (sum - expected));
        carry_in = carry_out.into();
    }
}

pub(super) fn constrain_private_sk_from_derive_final<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    prep_row: &[AB::Var],
    selector: AB::Expr,
) {
    let two16 = KoalaBear::from_u32(1 << 16);
    for (word_idx, carry_base) in [
        (0_usize, super::columns::CARRY_T1_BASE),
        (1_usize, super::columns::CARRY_T2_BASE),
        (2_usize, super::columns::CARRY_A_BASE),
        (3_usize, super::columns::CARRY_E_BASE),
    ] {
        let mut carry_in = AB::Expr::ZERO;
        for limb in 0..LIMBS_PER_WORD {
            let carry_out = row[carry_base + limb].clone();
            constrain_carry_max::<AB>(builder, row, carry_base + limb, 1);
            let sum = row[limb_col(WORD_A + word_idx, limb)].clone()
                + prep_row[limb_col(WORD_A + word_idx, limb)].clone()
                + carry_in;
            let expected =
                row[private_sk_limb_col(word_idx, limb)].clone() + carry_out.clone() * two16;
            builder.assert_zero(selector.clone() * (sum - expected));
            carry_in = carry_out.into();
        }
    }
}

pub(super) fn constrain_carry_max<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    carry_col: usize,
    max: u32,
) {
    let width = carry_bit_width(carry_col);
    let mut packed = AB::Expr::ZERO;
    for bit in 0..width {
        let b = row[carry_bit_col(carry_col, bit)].clone();
        builder.assert_bool(b.clone());
        packed += b * KoalaBear::from_u32(1 << bit);
    }
    builder.assert_eq(row[carry_col].clone(), packed);

    match max {
        1 => {}
        3 => {}
        4 => {
            let b0 = row[carry_bit_col(carry_col, 0)].clone();
            let b1 = row[carry_bit_col(carry_col, 1)].clone();
            let b2 = row[carry_bit_col(carry_col, 2)].clone();
            builder.assert_zero(b2 * (b1 + b0));
        }
        _ => unreachable!("unsupported carry bound"),
    }
}

pub(super) fn pack_bits<AB: AirBuilder<F = KoalaBear>>(
    row: &[AB::Var],
    bit_base: usize,
) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for i in (0..64).rev() {
        acc = acc * KoalaBear::TWO + row[bit_base + i].clone();
    }
    acc
}

pub(super) fn xor2_expr<AB: AirBuilder<F = KoalaBear>>(x: AB::Expr, y: AB::Expr) -> AB::Expr {
    x.clone() + y.clone() - (x * y) * KoalaBear::TWO
}

pub(super) fn xor3_expr<AB: AirBuilder<F = KoalaBear>>(
    x: AB::Expr,
    y: AB::Expr,
    z: AB::Expr,
) -> AB::Expr {
    xor2_expr::<AB>(xor2_expr::<AB>(x, y), z)
}

fn pack_small_sigma0_limb<B: AirBuilder<F = KoalaBear>>(row: &[B::Var], limb: usize) -> B::Expr {
    let mut out = B::Expr::ZERO;
    for bit in 0..16 {
        let b = small_sigma0_bit::<B>(row, limb * 16 + bit);
        out += b * KoalaBear::from_u32(1 << bit);
    }
    out
}

fn pack_small_sigma1_limb<B: AirBuilder<F = KoalaBear>>(row: &[B::Var], limb: usize) -> B::Expr {
    let mut out = B::Expr::ZERO;
    for bit in 0..16 {
        let b = small_sigma1_bit::<B>(row, limb * 16 + bit);
        out += b * KoalaBear::from_u32(1 << bit);
    }
    out
}

fn small_sigma0_bit<B: AirBuilder<F = KoalaBear>>(row: &[B::Var], bit: usize) -> B::Expr {
    xor3_expr::<B>(
        lag_bit_expr::<B>(row, 14, (bit + 1) % 64),
        lag_bit_expr::<B>(row, 14, (bit + 8) % 64),
        if bit + 7 < 64 {
            lag_bit_expr::<B>(row, 14, bit + 7)
        } else {
            B::Expr::ZERO
        },
    )
}

fn small_sigma1_bit<B: AirBuilder<F = KoalaBear>>(row: &[B::Var], bit: usize) -> B::Expr {
    xor3_expr::<B>(
        lag_bit_expr::<B>(row, 1, (bit + 19) % 64),
        lag_bit_expr::<B>(row, 1, (bit + 61) % 64),
        if bit + 6 < 64 {
            lag_bit_expr::<B>(row, 1, bit + 6)
        } else {
            B::Expr::ZERO
        },
    )
}

fn lag_bit_expr<B: AirBuilder<F = KoalaBear>>(row: &[B::Var], lag: usize, bit: usize) -> B::Expr {
    let base = match lag {
        1 => LAG1_BIT_BASE,
        14 => LAG14_BIT_BASE,
        _ => unreachable!("only lag=1 and lag=14 are bit-addressed in schedule sigmas"),
    };
    row[base + bit].clone().into()
}
