use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12};
use ark_ff::{Field as _, PrimeField};
use rand::{RngExt, rngs::StdRng};
use solana_bn254::backend::{Fq2, Fq6, Fq12, U256};
use std::sync::LazyLock;

static RADIX: LazyLock<ArkFq> = LazyLock::new(|| ArkFq::from(2u64).pow([256]));

pub fn raw(value: ArkFq) -> U256 {
    U256::new((value * *RADIX).into_bigint().0)
}

pub fn ours2(value: ArkFq2) -> Fq2 {
    Fq2::from_montgomery(raw(value.c0), raw(value.c1)).unwrap()
}

pub fn ours6(value: ArkFq6) -> Fq6 {
    Fq6::new(ours2(value.c0), ours2(value.c1), ours2(value.c2))
}

pub fn ours12(value: ArkFq12) -> Fq12 {
    Fq12::new(ours6(value.c0), ours6(value.c1))
}

pub fn check2(actual: Fq2, expected: ArkFq2) {
    // Construct expectations entirely with arkworks. Exact raw equality also
    // checks the Montgomery radix and canonicality of every output coefficient.
    assert_eq!(actual.to_montgomery(), (raw(expected.c0), raw(expected.c1)));
}

pub fn check6(actual: Fq6, expected: ArkFq6) {
    for (a, b) in actual
        .to_coefficients()
        .into_iter()
        .zip([expected.c0, expected.c1, expected.c2])
    {
        check2(a, b);
    }
}

pub fn check12(actual: Fq12, expected: ArkFq12) {
    for (a, b) in actual
        .to_coefficients()
        .into_iter()
        .zip([expected.c0, expected.c1])
    {
        check6(a, b);
    }
}

pub fn random2(rng: &mut StdRng) -> ArkFq2 {
    let mut coefficient = || loop {
        let mut limbs = rng.random::<[u64; 4]>();
        limbs[3] &= (1 << 62) - 1;
        if let Some(value) = ArkFq::from_bigint(ark_ff::BigInt(limbs)) {
            return value;
        }
    };
    ArkFq2::new(coefficient(), coefficient())
}

pub fn random6(rng: &mut StdRng) -> ArkFq6 {
    ArkFq6::new(random2(rng), random2(rng), random2(rng))
}

pub fn random12(rng: &mut StdRng) -> ArkFq12 {
    ArkFq12::new(random6(rng), random6(rng))
}
