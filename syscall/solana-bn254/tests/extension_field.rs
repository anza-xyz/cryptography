use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2};
use ark_ff::{AdditiveGroup, Field as _, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Field, Fq, Fq2, U256};

fn raw(a: ArkFq) -> U256 {
    U256::new((a * ArkFq::from(2u64).pow([256])).into_bigint().0)
}
fn ours(a: ArkFq2) -> Fq2 {
    Fq2::from_montgomery(raw(a.c0), raw(a.c1)).unwrap()
}
fn check(actual: Fq2, expected: ArkFq2) {
    // Exact limbs also require canonical coefficients; the oracle never calls
    // the implementation's conversion or arithmetic to construct expectations.
    assert_eq!(actual.to_montgomery(), (raw(expected.c0), raw(expected.c1)));
}
fn random(rng: &mut StdRng) -> ArkFq2 {
    let mut coefficient = || loop {
        let mut limbs = rng.random::<[u64; 4]>();
        limbs[3] &= (1 << 62) - 1;
        if let Some(v) = ArkFq::from_bigint(ark_ff::BigInt(limbs)) {
            return v;
        }
    };
    ArkFq2::new(coefficient(), coefficient())
}
fn pair(a: ArkFq2, b: ArkFq2) {
    let x = ours(a);
    let y = ours(b);
    check(x + y, a + b);
    check(x - y, a - b);
    check(x * y, a * b);
}
fn unary(a: ArkFq2) {
    let x = ours(a);
    check(x.square(), a.square());
    check(-x, -a);
    match (x.inverse(), a.inverse()) {
        (Some(v), Some(expected)) => {
            check(v, expected);
            assert_eq!(x * v, Fq2::ONE);
        }
        (None, None) => assert_eq!(x, Fq2::ZERO),
        _ => panic!("inverse mismatch"),
    }
}
#[test]
fn representation_and_range_boundaries() {
    assert_eq!(Fq::MODULUS.0, ArkFq::MODULUS.0);
    assert_eq!(Fq::MODULUS.0[0] % 4, 3);
    check(Fq2::ZERO, ArkFq2::ZERO);
    check(Fq2::ONE, ArkFq2::from(1u64));
    let mut last = Fq::MODULUS;
    last.0[0] -= 1;
    assert!(Fq2::from_montgomery(last, last).is_some());
    for invalid in [
        Fq::MODULUS,
        U256::new([u64::MAX; 4]),
        U256::new([0, 0, 0, 1 << 63]),
    ] {
        assert_eq!(Fq2::from_montgomery(invalid, U256::zero()), None);
        assert_eq!(Fq2::from_montgomery(U256::zero(), invalid), None);
    }
}
#[test]
fn arithmetic_boundaries_match_arkworks() {
    let base = [
        ArkFq::ZERO,
        ArkFq::from(1u64),
        ArkFq::from(2u64),
        -ArkFq::from(1u64),
        -ArkFq::from(2u64),
        ArkFq::from(2u64).pow([64]),
        ArkFq::from(2u64).pow([128]),
        ArkFq::from(2u64).pow([253]),
    ];
    let values: Vec<_> = base
        .into_iter()
        .flat_map(|a| base.into_iter().map(move |b| ArkFq2::new(a, b)))
        .collect();
    for &a in &values {
        unary(a);
        check(ours(a).conjugate(), a.pow(ArkFq::MODULUS.0));
        for &b in &values {
            pair(a, b);
        }
    }
}
#[test]
fn seeded_arithmetic_matches_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6671_325f_6172_6974);
    for _ in 0..4096 {
        let a = random(&mut rng);
        let b = random(&mut rng);
        pair(a, b);
        unary(a);
    }
}
#[test]
fn dependent_chains_match_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6671_325f_6368_6169);
    for _ in 0..64 {
        let mut expected = random(&mut rng);
        let mut actual = ours(expected);
        for _ in 0..32 {
            let a = random(&mut rng);
            let b = random(&mut rng);
            expected = (expected + a).square() * b - a;
            actual = (actual + ours(a)).square() * ours(b) - ours(a);
            check(actual, expected);
            if let Some(v) = expected.inverse() {
                expected = v;
                actual = actual.inverse().unwrap();
                check(actual, expected);
            }
        }
    }
}

#[test]
fn raw_montgomery_boundaries_match_arkworks() {
    // Conventional field boundaries need not map to raw Montgomery boundaries.
    // Construct the latter explicitly, then decode them using arkworks alone.
    let mut values = vec![U256::zero(), U256::one(), U256::new([2, 0, 0, 0])];
    for amount in [1, 2] {
        let mut last = Fq::MODULUS;
        last.0[0] -= amount;
        values.push(last);
    }
    for bit in [64usize, 128, 192, 253] {
        let mut power = [0; 4];
        power[bit / 64] = 1 << (bit % 64);
        values.push(U256::new(power));
        let mut below = power;
        below[bit / 64] -= 1;
        for limb in &mut below[..bit / 64] {
            *limb = u64::MAX;
        }
        values.push(U256::new(below));
        power[0] += 1;
        values.push(U256::new(power));
    }
    let r_inverse = ArkFq::from(2u64).pow([256]).inverse().unwrap();
    let decode = |raw: U256| ArkFq::from_bigint(ark_ff::BigInt(raw.0)).unwrap() * r_inverse;
    let pairs: Vec<_> = values
        .iter()
        .flat_map(|&a| {
            values.iter().map(move |&b| {
                (
                    Fq2::from_montgomery(a, b).unwrap(),
                    ArkFq2::new(decode(a), decode(b)),
                )
            })
        })
        .collect();
    for &(actual, expected) in &pairs {
        check(actual.square(), expected.square());
        check(actual * actual, expected.square());
        for &(rhs, oracle_rhs) in &pairs {
            check(actual * rhs, expected * oracle_rhs);
        }
    }
}
