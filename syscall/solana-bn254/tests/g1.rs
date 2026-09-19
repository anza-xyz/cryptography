//! Independent checks of affine results, canonical coordinates, and encodings.
use ark_bn254::{Fq as ArkFq, Fr as ArkFr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field as _, PrimeField};
use num_bigint::BigUint;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Field, Fq, U256},
    g1::Affine,
};

fn radix() -> ArkFq {
    ArkFq::from(2u64).pow([256u64])
}
fn mont(value: ArkFq) -> U256 {
    U256::new((value * radix()).into_bigint().0)
}
fn ours(point: G1Affine) -> Affine {
    if point.infinity {
        Affine::IDENTITY
    } else {
        Affine::from_montgomery(mont(point.x), mont(point.y)).unwrap()
    }
}
fn bytes(point: G1Affine, be: bool) -> [u8; 64] {
    let mut result = [0; 64];
    if !point.infinity {
        for (value, coordinate) in [point.x, point.y]
            .iter()
            .zip(result.as_chunks_mut::<32>().0)
        {
            for (limb, chunk) in value
                .into_bigint()
                .0
                .iter()
                .zip(coordinate.as_chunks_mut::<8>().0)
            {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
            if be {
                coordinate.reverse();
            }
        }
    }
    result
}
fn check(actual: Affine, expected: G1Affine) {
    let coordinates = if expected.infinity {
        (U256::zero(), U256::zero())
    } else {
        (mont(expected.x), mont(expected.y))
    };
    // Exact raw limbs test canonical output and both coordinates independently.
    assert_eq!(actual.to_montgomery(), coordinates);
    assert_eq!(actual.to_be_bytes(), bytes(expected, true));
    assert_eq!(actual.to_le_bytes(), bytes(expected, false));
}
fn random_point(rng: &mut StdRng) -> G1Affine {
    loop {
        let x = ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
        if let Some(mut y) = (x.square() * x + ArkFq::from(3u64)).sqrt() {
            if rng.random::<bool>() {
                y = -y;
            }
            return G1Affine::new_unchecked(x, y);
        }
    }
}

#[test]
fn montgomery_constructor_checks_range_and_curve() {
    assert_eq!(
        Affine::from_montgomery(U256::zero(), U256::zero()),
        Some(Affine::IDENTITY)
    );
    for invalid in [Fq::MODULUS, U256::new([u64::MAX; 4])] {
        assert_eq!(Affine::from_montgomery(invalid, mont(ArkFq::from(2))), None);
        assert_eq!(Affine::from_montgomery(mont(ArkFq::from(1)), invalid), None);
    }
    assert_eq!(
        Affine::from_montgomery(mont(ArkFq::from(1)), mont(ArkFq::from(3))),
        None
    );
    check(ours(G1Affine::generator()), G1Affine::generator());
}

#[test]
fn point_encodings_preserve_flags_and_zero_behavior() {
    for be in [false, true] {
        let decode = |data: &[u8; 64]| {
            if be {
                Affine::from_be_bytes(data)
            } else {
                Affine::from_le_bytes(data)
            }
        };
        let high = if be { 32 } else { 63 };
        let generator = G1Affine::generator();
        let original = bytes(generator, be);
        for (flag, expected) in [
            (0, Some(ours(generator))),
            (0x80, Some(ours(generator))),
            (0x40, Some(Affine::IDENTITY)),
            (0xc0, None),
        ] {
            let mut data = original;
            data[high] |= flag;
            assert_eq!(decode(&data), expected);
        }
        let mut zero = [0; 64];
        assert_eq!(decode(&zero), Some(Affine::IDENTITY));
        zero[high] = 0x80;
        assert_eq!(decode(&zero), None);
        zero[high] = 0x40;
        assert_eq!(decode(&zero), Some(Affine::IDENTITY));
        let mut off_curve = bytes(G1Affine::new_unchecked(ArkFq::from(1), ArkFq::from(3)), be);
        assert_eq!(decode(&off_curve), None);
        off_curve[high] |= 0x40;
        assert_eq!(decode(&off_curve), Some(Affine::IDENTITY));
        for offset in [0, 32] {
            let mut data = original;
            let mut q = ArkFq::MODULUS.to_bytes_le();
            if be {
                q.reverse();
            }
            data[offset..offset + 32].copy_from_slice(&q);
            data[high] |= 0x40;
            assert_eq!(decode(&data), None);
        }
    }
}

#[test]
fn seeded_encoding_roundtrips() {
    let mut rng = StdRng::seed_from_u64(0x6731_5f65_6e63_7631);
    for _ in 0..256 {
        let p = random_point(&mut rng);
        assert_eq!(Affine::from_be_bytes(&bytes(p, true)), Some(ours(p)));
        assert_eq!(Affine::from_le_bytes(&bytes(p, false)), Some(ours(p)));
        check(ours(p), p);
        check(-ours(p), -p);
    }
    check(-Affine::IDENTITY, G1Affine::identity());
}

#[test]
fn addition_matches_arkworks_with_exceptional_cases() {
    let mut rng = StdRng::seed_from_u64(0x6731_5f61_6464_7631);
    for _ in 0..256 {
        let p = random_point(&mut rng);
        let q = random_point(&mut rng);
        for rhs in [q, p, -p, G1Affine::identity()] {
            check(ours(p) + ours(rhs), (p + rhs).into_affine());
        }
        check(Affine::IDENTITY + ours(p), p);
    }
    check(Affine::IDENTITY + Affine::IDENTITY, G1Affine::identity());
}

#[test]
fn raw_scalar_multiplication_matches_arkworks() {
    let mut rng = StdRng::seed_from_u64(0x6731_5f6d_756c_7631);
    for _ in 0..256 {
        let p = random_point(&mut rng);
        let scalar = U256::new(rng.random());
        check(
            ours(p).mul_scalar(&scalar),
            p.mul_bigint(BigInt(scalar.0)).into_affine(),
        );
    }
}

#[test]
fn every_scalar_bit_and_order_boundaries() {
    let mut rng = StdRng::seed_from_u64(0x6731_5f62_6974_7631);
    let p = random_point(&mut rng);
    let mut scalars = vec![
        BigInt::from(0u64),
        ArkFr::MODULUS,
        BigInt([u64::MAX; 4]),
        BigInt([0xaaaa_aaaa_aaaa_aaaa; 4]),
        BigInt([0x5555_5555_5555_5555; 4]),
    ];
    for mut value in [ArkFr::MODULUS; 2].into_iter().enumerate() {
        if value.0 == 0 {
            value.1.sub_with_borrow(&BigInt::from(1u64));
        } else {
            value.1.add_with_carry(&BigInt::from(1u64));
        }
        scalars.push(value.1);
    }
    for bit in 0..256 {
        let mut limbs = [0; 4];
        limbs[bit / 64] = 1u64 << (bit % 64);
        let power = BigInt(limbs);
        let mut before = power;
        before.sub_with_borrow(&BigInt::from(1u64));
        let mut after = power;
        after.add_with_carry(&BigInt::from(1u64));
        scalars.extend([before, power, after]);
    }
    for scalar in scalars {
        check(
            ours(p).mul_scalar(&U256::new(scalar.0)),
            p.mul_bigint(scalar).into_affine(),
        );
        assert_eq!(
            Affine::IDENTITY.mul_scalar(&U256::new(scalar.0)),
            Affine::IDENTITY
        );
    }
}

#[test]
fn scalar_reduction_sign_and_dispatch_boundaries() {
    let one = BigUint::from(1u8);
    let radix = &one << 256usize;
    let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
    let short_limit = &one << 128usize;
    let trivial_limit = &one << 64usize;
    let mut scalars = Vec::new();
    for multiple in 0..=5u8 {
        for offset in [
            BigUint::from(0u8),
            trivial_limit.clone(),
            short_limit.clone(),
            &r >> 1usize,
            &r - &trivial_limit,
            &r - &short_limit,
        ] {
            let center = &r * multiple + offset;
            for value in [
                (center >= one).then(|| &center - &one),
                Some(center.clone()),
                Some(center + &one),
            ]
            .into_iter()
            .flatten()
            {
                if value < radix {
                    let mut limbs = [0; 4];
                    let digits = value.to_u64_digits();
                    limbs[..digits.len()].copy_from_slice(&digits);
                    scalars.push(BigInt(limbs));
                }
            }
        }
    }
    let mut rng = StdRng::seed_from_u64(0x6731_5f63_656e_7472);
    let p = random_point(&mut rng);
    for point in [
        G1Affine::generator(),
        p,
        -p,
        random_point(&mut rng),
        G1Affine::identity(),
    ] {
        for scalar in &scalars {
            check(
                ours(point).mul_scalar(&U256::new(scalar.0)),
                point.mul_bigint(*scalar).into_affine(),
            );
        }
    }
}

#[test]
fn dependent_addition_and_doubling_chains() {
    let mut rng = StdRng::seed_from_u64(0x6731_5f63_6861_696e);
    for _ in 0..32 {
        let mut expected = random_point(&mut rng);
        let mut actual = ours(expected);
        for step in 0..32 {
            let rhs = if step % 3 == 0 {
                expected
            } else {
                random_point(&mut rng)
            };
            actual = actual + ours(rhs);
            expected = (expected + rhs).into_affine();
            check(actual, expected);
        }
    }
}
