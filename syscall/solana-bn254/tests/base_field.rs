//! Exact checks of BN254 Fq arithmetic against arkworks.
//!
//! Oracles operate on raw integers and construct Montgomery factors using
//! arkworks alone. Exact limb comparisons also check canonical outputs.

use ark_bn254::Fq as ArkFq;
use ark_ff::{BigInt, Field as _, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Field, Fq, MontgomeryBackend, U256};

type B = Backend<Fq>;

fn raw(value: ArkFq) -> U256 {
    U256::new(value.into_bigint().0)
}

fn integer(value: &U256) -> ArkFq {
    ArkFq::from_bigint(BigInt(value.0)).expect("test operand must be canonical")
}

fn random_operand(rng: &mut StdRng) -> U256 {
    raw(ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()))
}

fn radix() -> ArkFq {
    ArkFq::from(2u64).pow([256u64])
}

fn boundaries(bits: impl IntoIterator<Item = usize>) -> Vec<U256> {
    let one = ArkFq::from(1u64);
    let mut values = vec![
        U256::zero(),
        U256::one(),
        U256::new([2, 0, 0, 0]),
        U256::new([3, 0, 0, 0]),
        raw(radix()),
        U256::new([u64::MAX, u64::MAX, u64::MAX, 0]),
        U256::new([u64::MAX, u64::MAX, u64::MAX, Fq::MODULUS.0[3] - 1]),
        U256::new([
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x1555_5555_5555_5555,
        ]),
        U256::new([
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0x2aaa_aaaa_aaaa_aaaa,
        ]),
    ];
    for delta in [1u64, 2, 3, 4, 7, 8, 15, 16, 256, 65_536, u64::MAX] {
        values.push(raw(-ArkFq::from(delta)));
    }
    for bit in bits {
        let mut limbs = [0; 4];
        limbs[bit / 64] = 1 << (bit % 64);
        let power = integer(&U256::new(limbs));
        values.extend([raw(power - one), raw(power), raw(power + one)]);
    }
    values
}

fn check_binary(a: &U256, b: &U256, r_inverse: ArkFq) {
    let x = integer(a);
    let y = integer(b);
    for (name, actual, expected) in [
        ("add", B::add(a, b), x + y),
        ("sub", B::sub(a, b), x - y),
        ("mul", B::mul(a, b), x * y * r_inverse),
    ] {
        assert_eq!(actual, raw(expected), "{name}: a={a:?}, b={b:?}");
    }
}

fn check_unary(a: &U256, r: ArkFq, r_inverse: ArkFq) {
    let x = integer(a);
    for (name, actual, expected) in [
        ("neg", B::neg(a), -x),
        ("sqr", B::sqr(a), x.square() * r_inverse),
        ("to_mont", B::to_mont(a), x * r),
        ("from_mont", B::from_mont(a), x * r_inverse),
    ] {
        assert_eq!(actual, raw(expected), "{name}: a={a:?}");
    }
    assert_eq!(B::from_mont(&B::to_mont(a)), *a);
}

#[test]
fn parameters_match_arkworks_and_fixed_radix() {
    assert_eq!(Fq::MODULUS.0, ArkFq::MODULUS.0);
    assert_eq!(Fq::INV.wrapping_mul(Fq::MODULUS.0[0]), u64::MAX);
    assert_eq!(Fq::R2, raw(radix().square()));
    assert_eq!(
        B::to_mont(&U256::one()),
        U256::new([
            0xd35d438dc58f0d9d,
            0x0a78eb28f5c70b3d,
            0x666ea36f7879462c,
            0x0e0a77c19a07df2f,
        ])
    );
}

#[test]
fn reduction_checks_all_limbs() {
    let mut values = boundaries([63, 64, 127, 128, 191, 192, 253]);
    values.extend([Fq::MODULUS, U256::new([u64::MAX; 4])]);
    // Equal higher limbs force the comparison to inspect each lower limb.
    for i in 0..4 {
        for delta in [-1i64, 1] {
            let mut value = Fq::MODULUS;
            value.0[i] = value.0[i].checked_add_signed(delta).unwrap();
            values.push(value);
        }
    }
    for value in values {
        assert_eq!(
            B::is_reduced(&value),
            ArkFq::from_bigint(BigInt(value.0)).is_some(),
            "value={value:?}"
        );
    }
}

#[test]
fn binary_boundaries_match_arkworks() {
    let r_inverse = radix().inverse().unwrap();
    let values = boundaries([1, 63, 64, 65, 127, 128, 129, 191, 192, 193, 252, 253]);
    for a in &values {
        for b in &values {
            check_binary(a, b, r_inverse);
        }
    }
}

#[test]
fn unary_and_conversion_boundaries_match_arkworks() {
    let r = radix();
    let r_inverse = r.inverse().unwrap();
    for a in boundaries(0..254) {
        check_unary(&a, r, r_inverse);
    }
}

#[test]
fn seeded_arithmetic_matches_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6671_5f61_7269_7468);
    let r = radix();
    let r_inverse = r.inverse().unwrap();
    for _ in 0..4096 {
        let a = random_operand(&mut rng);
        let b = random_operand(&mut rng);
        check_binary(&a, &b, r_inverse);
        check_unary(&a, r, r_inverse);
    }
}

#[test]
fn dependent_chains_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6671_5f63_6861_696e);
    let r_inverse = radix().inverse().unwrap();
    for chain in 0..64 {
        let mut actual = random_operand(&mut rng);
        let mut expected = integer(&actual);
        for step in 0..64 {
            let operand = random_operand(&mut rng);
            let x = integer(&operand);
            (actual, expected) = match step % 5 {
                0 => (B::add(&actual, &operand), expected + x),
                1 => (B::sub(&actual, &operand), expected - x),
                2 => (B::mul(&actual, &operand), expected * x * r_inverse),
                3 => (B::sqr(&actual), expected.square() * r_inverse),
                _ => (B::neg(&actual), -expected),
            };
            assert_eq!(actual, raw(expected), "chain={chain}, step={step}");
        }
    }
}
