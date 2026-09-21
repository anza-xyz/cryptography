use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12};
use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Field, Fq, Fq2, Fq6, Fq12, U256};

#[path = "common/tower.rs"]
mod tower;
use tower::*;

fn pair6(a: ArkFq6, b: ArkFq6) {
    let (x, y) = (ours6(a), ours6(b));
    check6(x + y, a + b);
    check6(x - y, a - b);
    check6(x * y, a * b);
}

fn pair12(a: ArkFq12, b: ArkFq12) {
    let (x, y) = (ours12(a), ours12(b));
    check12(x + y, a + b);
    check12(x - y, a - b);
    check12(x * y, a * b);
}

fn unary6(a: ArkFq6) {
    let x = ours6(a);
    check6(-x, -a);
    check6(x.square(), a.square());
    assert_eq!(x.inverse(), a.inverse().map(ours6));
    if let Some(inverse) = x.inverse() {
        assert_eq!(x * inverse, Fq6::ONE);
    }
}

fn unary12(a: ArkFq12) {
    let x = ours12(a);
    check12(-x, -a);
    check12(x.square(), a.square());
    assert_eq!(x.inverse(), a.inverse().map(ours12));
    if let Some(inverse) = x.inverse() {
        assert_eq!(x * inverse, Fq12::ONE);
    }
    check12(x.conjugate(), ArkFq12::new(a.c0, -a.c1));
}

#[test]
fn representation_and_tower_relations() {
    assert_eq!(Fq::MODULUS.0, ArkFq::MODULUS.0);
    assert_eq!(Fq6::default(), Fq6::ZERO);
    assert_eq!(Fq12::default(), Fq12::ZERO);
    check6(Fq6::ZERO, ArkFq6::ZERO);
    check6(Fq6::ONE, ArkFq6::ONE);
    check12(Fq12::ZERO, ArkFq12::ZERO);
    check12(Fq12::ONE, ArkFq12::ONE);
    assert_eq!(Fq6::ZERO.inverse(), None);
    assert_eq!(Fq12::ZERO.inverse(), None);

    let v = Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO);
    let xi = ArkFq2::new(ArkFq::from(9), ArkFq::ONE);
    assert_eq!(v * v * v, Fq6::new(ours2(xi), Fq2::ZERO, Fq2::ZERO));
    let w = Fq12::new(Fq6::ZERO, Fq6::ONE);
    assert_eq!(w.square(), Fq12::new(v, Fq6::ZERO));

    // Independently establish that these binomials define fields.
    let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
    let cube_test = (q.pow(2) - 1u8) / 3u8;
    assert_ne!(xi.pow(cube_test.to_u64_digits()), ArkFq2::ONE);
    let square_test = (q.pow(6) - 1u8) / 2u8;
    let ark_v = ArkFq6::new(ArkFq2::ZERO, ArkFq2::ONE, ArkFq2::ZERO);
    assert_eq!(ark_v.pow(square_test.to_u64_digits()), -ArkFq6::ONE);
}

fn raw_boundaries() -> Vec<U256> {
    let mut values = vec![U256::zero(), U256::one(), U256::new([2, 0, 0, 0])];
    for amount in [1, 2] {
        let mut last = Fq::MODULUS;
        last.0[0] -= amount;
        values.push(last);
    }
    for bit in [64usize, 128, 192, 253] {
        let mut power = [0; 4];
        power[bit / 64] = 1 << (bit % 64);
        let mut below = power;
        below[bit / 64] -= 1;
        for limb in &mut below[..bit / 64] {
            *limb = u64::MAX;
        }
        values.push(U256::new(below));
        values.push(U256::new(power));
        power[0] += 1;
        values.push(U256::new(power));
    }
    values
}

fn raw12(words: [U256; 12]) -> (Fq12, ArkFq12) {
    let r_inverse = ArkFq::from(2u64).pow([256]).inverse().unwrap();
    let decode = |word: U256| ArkFq::from_bigint(ark_ff::BigInt(word.0)).unwrap() * r_inverse;
    let actual: [Fq2; 6] =
        core::array::from_fn(|i| Fq2::from_montgomery(words[2 * i], words[2 * i + 1]).unwrap());
    let expected: [ArkFq2; 6] =
        core::array::from_fn(|i| ArkFq2::new(decode(words[2 * i]), decode(words[2 * i + 1])));
    (
        Fq12::new(
            Fq6::new(actual[0], actual[1], actual[2]),
            Fq6::new(actual[3], actual[4], actual[5]),
        ),
        ArkFq12::new(
            ArkFq6::new(expected[0], expected[1], expected[2]),
            ArkFq6::new(expected[3], expected[4], expected[5]),
        ),
    )
}

#[test]
fn raw_montgomery_boundaries_match_arkworks() {
    let words = raw_boundaries();
    let mut cases = Vec::new();
    for (shift, &word) in words.iter().enumerate() {
        cases.push(raw12([word; 12]));
        cases.push(raw12(core::array::from_fn(|i| {
            words[(i + shift) % words.len()]
        })));
    }
    for i in 0..12 {
        let mut sparse = [U256::zero(); 12];
        sparse[i] = words[3]; // Raw q-1, in every coefficient position.
        cases.push(raw12(sparse));
    }
    for &(actual, expected) in &cases {
        check12(actual, expected);
        unary12(expected);
        for a in [expected.c0, expected.c1] {
            unary6(a);
        }
        for &(rhs, oracle_rhs) in &cases {
            check12(actual + rhs, expected + oracle_rhs);
            check12(actual - rhs, expected - oracle_rhs);
            check12(actual * rhs, expected * oracle_rhs);
            pair6(expected.c0, oracle_rhs.c0);
            pair6(expected.c1, oracle_rhs.c1);
        }
    }
}

#[test]
fn seeded_arithmetic_matches_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x746f_7765_725f_7631);
    for _ in 0..4096 {
        let a = random12(&mut rng);
        let b = random12(&mut rng);
        pair6(a.c0, b.c0);
        pair12(a, b);
        unary6(a.c0);
        unary12(a);
    }
}

#[test]
fn dependent_chains_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x746f_7765_725f_6368);
    for _ in 0..64 {
        let mut expected = random12(&mut rng);
        let mut actual = ours12(expected);
        let mut expected6 = expected.c0;
        let mut actual6 = ours6(expected6);
        for step in 0..32 {
            let a = random12(&mut rng);
            let b = random12(&mut rng);
            expected = (expected + a).square() * b - a;
            actual = (actual + ours12(a)).square() * ours12(b) - ours12(a);
            expected6 = (expected6 + a.c0).square() * b.c0 - a.c0;
            actual6 = (actual6 + ours6(a.c0)).square() * ours6(b.c0) - ours6(a.c0);
            check12(actual, expected);
            check6(actual6, expected6);
            if let Some(inverse) = expected.inverse() {
                expected = inverse;
                actual = actual.inverse().unwrap();
            }
            if let Some(inverse) = expected6.inverse() {
                expected6 = inverse;
                actual6 = actual6.inverse().unwrap();
            }
            expected.frobenius_map_in_place(step);
            actual = actual.frobenius(step);
            expected6.frobenius_map_in_place(step);
            actual6 = actual6.frobenius(step);
            check12(actual, expected);
            check6(actual6, expected6);
        }
    }
}

#[test]
fn sparse_multiplication_matches_dense_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x746f_7765_725f_7370);
    let mut boundary = Fq::MODULUS;
    boundary.0[0] -= 1;
    let (_, boundary) = raw12([boundary; 12]);
    for i in 0..1024 {
        let a = if i == 0 { boundary } else { random12(&mut rng) };
        let b = if i == 0 { boundary } else { random12(&mut rng) };
        let [b0, b3, b4] = [b.c0.c0, b.c1.c0, b.c1.c1];
        for [b0, b3, b4] in [
            [ArkFq2::ZERO; 3],
            [b0, ArkFq2::ZERO, ArkFq2::ZERO],
            [ArkFq2::ZERO, b3, ArkFq2::ZERO],
            [ArkFq2::ZERO, ArkFq2::ZERO, b4],
            [b0, b3, b4],
        ] {
            let factor = ArkFq12::new(
                ArkFq6::new(b0, ArkFq2::ZERO, ArkFq2::ZERO),
                ArkFq6::new(b3, b4, ArkFq2::ZERO),
            );
            check12(
                ours12(a).mul_by_034(&ours2(b0), &ours2(b3), &ours2(b4)),
                a * factor,
            );
            check6(
                ours6(a.c0).mul_by_01(&ours2(b0), &ours2(b3)),
                a.c0 * ArkFq6::new(b0, b3, ArkFq2::ZERO),
            );
            check6(
                ours6(a.c0).mul_by_fq2(&ours2(b0)),
                a.c0 * ArkFq6::new(b0, ArkFq2::ZERO, ArkFq2::ZERO),
            );
        }
        let v = ArkFq6::new(ArkFq2::ZERO, ArkFq2::ONE, ArkFq2::ZERO);
        check6(ours6(a.c0).mul_by_v(), a.c0 * v);
    }
}

#[test]
fn frobenius_matches_generic_exponentiation() {
    let mut rng = StdRng::seed_from_u64(0x746f_7765_725f_6672);
    let mut cases = vec![
        ArkFq12::ZERO,
        ArkFq12::ONE,
        random12(&mut rng),
        random12(&mut rng),
    ];
    for coefficient in 0..6 {
        // Basis values isolate every table multiplier, including u conjugation.
        let mut terms = [ArkFq2::ZERO; 6];
        terms[coefficient] = ArkFq2::new(ArkFq::ONE, ArkFq::ONE);
        cases.push(ArkFq12::new(
            ArkFq6::new(terms[0], terms[1], terms[2]),
            ArkFq6::new(terms[3], terms[4], terms[5]),
        ));
    }
    for a in cases {
        let actual = ours12(a);
        let actual6 = ours6(a.c0);
        let mut oracle = a;
        let mut oracle6 = a.c0;
        for power in 0..=24 {
            check12(actual.frobenius(power), oracle);
            check6(actual6.frobenius(power), oracle6);
            // Generic square/multiply exponentiation uses no Frobenius table.
            oracle = oracle.pow(ArkFq::MODULUS.0);
            oracle6 = oracle6.pow(ArkFq::MODULUS.0);
        }
        let reduced = usize::MAX % 12;
        check12(
            actual.frobenius(usize::MAX),
            a.pow(
                BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le())
                    .pow(reduced as u32)
                    .to_u64_digits(),
            ),
        );
        assert_eq!(
            actual6.frobenius(usize::MAX),
            actual6.frobenius(usize::MAX % 6)
        );
        assert_eq!(actual.conjugate(), actual.frobenius(6));
    }
}

#[test]
fn conjugation_does_not_assume_subgroup_membership() {
    let a = ArkFq12::new(ArkFq6::from(2u64), ArkFq6::ONE);
    let x = ours12(a);
    assert_eq!(x.conjugate().conjugate(), x);
    assert_ne!(x.conjugate(), x.inverse().unwrap());
    check12(
        x.conjugate(),
        a.pow(
            BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le())
                .pow(6)
                .to_u64_digits(),
        ),
    );
}
