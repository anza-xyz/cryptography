use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fr, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, models::CurveConfig};
use ark_ff::{BigInt, Field, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Fq2, U256},
    g2::Affine,
};

fn fq2(value: ArkFq2) -> Fq2 {
    let radix = ArkFq::from(2u64).pow([256]);
    let raw = |x: ArkFq| U256::new((x * radix).into_bigint().0);
    Fq2::from_montgomery(raw(value.c0), raw(value.c1)).unwrap()
}
fn ours(p: G2Affine) -> Affine {
    if p.infinity {
        Affine::IDENTITY
    } else {
        Affine::from_montgomery(fq2(p.x), fq2(p.y)).unwrap()
    }
}
fn bytes(p: G2Affine, be: bool) -> [u8; 128] {
    let mut out = [0; 128];
    if !p.infinity {
        for (c, chunk) in [p.x.c0, p.x.c1, p.y.c0, p.y.c1]
            .iter()
            .zip(out.as_chunks_mut::<32>().0)
        {
            for (limb, chunk) in c.into_bigint().0.iter().zip(chunk.as_chunks_mut::<8>().0) {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
        }
        if be {
            out[..64].reverse();
            out[64..].reverse();
        }
    }
    out
}
fn check(actual: Affine, p: G2Affine) {
    assert_eq!(actual, ours(p));
    assert_eq!(actual.to_le_bytes(), bytes(p, false));
    assert_eq!(actual.to_be_bytes(), bytes(p, true));
    if !p.infinity {
        assert_eq!(actual.to_montgomery(), (fq2(p.x), fq2(p.y)));
    }
}
fn random_fq(rng: &mut StdRng) -> ArkFq {
    loop {
        let mut limbs = rng.random::<[u64; 4]>();
        limbs[3] &= (1 << 62) - 1;
        if let Some(x) = ArkFq::from_bigint(BigInt(limbs)) {
            return x;
        }
    }
}
fn on_curve(rng: &mut StdRng) -> G2Affine {
    loop {
        let x = ArkFq2::new(random_fq(rng), random_fq(rng));
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, rng.random()) {
            return p;
        }
    }
}

#[test]
fn curve_constructor_encoding_and_identity() {
    assert_eq!(
        Affine::from_montgomery(Fq2::ZERO, Fq2::ZERO),
        Some(Affine::IDENTITY)
    );
    assert_eq!(Affine::from_montgomery(Fq2::ZERO, Fq2::ONE), None);
    assert!(Affine::IDENTITY.is_in_correct_subgroup());
    let mut rng = StdRng::seed_from_u64(0x6732_5f65_6e63_6f64);
    for p in [
        G2Affine::identity(),
        G2Affine::generator(),
        -G2Affine::generator(),
    ]
    .into_iter()
    .chain((0..64).map(|_| on_curve(&mut rng)))
    {
        let a = ours(p);
        check(a, p);
        assert_eq!(Affine::from_le_bytes(&bytes(p, false)), Some(a));
        assert_eq!(Affine::from_be_bytes(&bytes(p, true)), Some(a));
        check(-a, -p);
    }
}

#[test]
fn subgroup_test_matches_independent_order_multiplication() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f73_7562_6772);
    assert!(Affine::IDENTITY.is_in_correct_subgroup());
    for _ in 0..128 {
        let p = on_curve(&mut rng);
        // Affine mul_bigint is binary, with no GLV or Frobenius subgroup test.
        let expected = p.mul_bigint(Fr::MODULUS).into_affine().infinity;
        assert_eq!(ours(p).is_in_correct_subgroup(), expected);
        assert!(!expected);
        let torsion = p.mul_bigint(Fr::MODULUS).into_affine();
        assert!(!torsion.infinity);
        assert!(!ours(torsion).is_in_correct_subgroup());
        check(
            ours(torsion).mul_scalar(&U256::new(Fr::MODULUS.0)),
            torsion.mul_bigint(Fr::MODULUS).into_affine(),
        );
        // Clear using the full cofactor, independently of endomorphism logic.
        let subgroup = p.mul_bigint(ark_bn254::g2::Config::COFACTOR).into_affine();
        assert!(subgroup.mul_bigint(Fr::MODULUS).into_affine().infinity);
        assert!(ours(subgroup).is_in_correct_subgroup());
        assert!(ours(-subgroup).is_in_correct_subgroup());
        assert!(!ours(-torsion).is_in_correct_subgroup());
        let mixed = (subgroup + torsion).into_affine();
        assert!(!mixed.mul_bigint(Fr::MODULUS).into_affine().infinity);
        assert!(!ours(mixed).is_in_correct_subgroup());
    }
}

#[test]
fn addition_and_chains_match_arkworks_on_entire_twist() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f61_6464_7631);
    for _ in 0..128 {
        let p = on_curve(&mut rng);
        let q = on_curve(&mut rng);
        for rhs in [p, q, -p, G2Affine::identity()] {
            check(ours(p) + ours(rhs), (p + rhs).into_affine());
        }
        check(Affine::IDENTITY + ours(p), p);
    }
    let mut p = G2Affine::generator();
    let mut a = ours(p);
    for _ in 0..64 {
        let q = on_curve(&mut rng);
        p = (p + p + q).into_affine();
        a = a + a + ours(q);
        check(a, p);
    }
}

#[test]
fn raw_scalars_match_binary_oracle_including_nonsubgroup_points() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f6d_756c_7631);
    for i in 0..128 {
        let p = if i % 2 == 0 {
            on_curve(&mut rng)
        } else {
            G2Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine()
        };
        let scalar = rng.random::<[u64; 4]>();
        check(
            ours(p).mul_scalar(&U256::new(scalar)),
            p.mul_bigint(scalar).into_affine(),
        );
    }
}

#[test]
fn every_scalar_bit_and_group_order_boundaries() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f62_6974_7331);
    let points = [
        G2Affine::identity(),
        G2Affine::generator(),
        -G2Affine::generator(),
        on_curve(&mut rng),
    ];
    let mut scalars = vec![BigInt::from(0u64), BigInt([u64::MAX; 4])];
    for bit in 0..256 {
        let mut s = BigInt([0u64; 4]);
        s.0[bit / 64] = 1 << (bit % 64);
        scalars.push(s);
        if bit > 0 {
            let mut below = s;
            for limb in &mut below.0 {
                let (v, borrow) = limb.overflowing_sub(1);
                *limb = v;
                if !borrow {
                    break;
                }
            }
            scalars.push(below);
        }
    }
    for delta in [-1, 0, 1] {
        let mut s = Fr::MODULUS;
        s.0[0] = s.0[0].wrapping_add_signed(delta);
        scalars.push(s);
    }
    for p in points {
        for s in &scalars {
            check(
                ours(p).mul_scalar(&U256::new(s.0)),
                p.mul_bigint(s.0).into_affine(),
            );
        }
    }
}

fn checked_scalar_boundaries() -> Vec<BigInt<4>> {
    use ark_ff::BigInteger;
    use num_bigint::BigUint;
    let one = BigUint::from(1u8);
    let radix = &one << 256usize;
    let r = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    let mut values = Vec::new();
    let mut neighbors = |value: BigUint| {
        let mut push = |s: BigUint| {
            if s < radix {
                let words = s.to_u64_digits();
                let mut limbs = [0u64; 4];
                limbs[..words.len()].copy_from_slice(&words);
                values.push(BigInt(limbs));
            }
        };
        if value > BigUint::from(0u8) {
            push(&value - &one);
        }
        push(value.clone());
        push(value + &one);
    };
    for bit in 0..=256 {
        neighbors(&one << bit);
    }
    for multiple in 0..=5u8 {
        neighbors(&r * multiple);
        neighbors(&r * multiple + (&r >> 1usize));
        for bits in [64usize, 128] {
            let small = (&one << bits) - &one;
            let base = &r * multiple;
            if base >= small {
                neighbors(&base - &small);
            }
            neighbors(base + small);
        }
    }
    values
}

#[test]
fn checked_scalar_boundaries_match_binary_oracle() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f63_656e_7431);
    let arbitrary = on_curve(&mut rng);
    let subgroup = arbitrary
        .mul_bigint(ark_bn254::g2::Config::COFACTOR)
        .into_affine();
    assert!(subgroup.mul_bigint(Fr::MODULUS).into_affine().infinity);
    let scalars = checked_scalar_boundaries();
    for p in [
        G2Affine::identity(),
        G2Affine::generator(),
        -G2Affine::generator(),
        subgroup,
    ] {
        for s in &scalars {
            let expected = p.mul_bigint(s.0).into_affine();
            check(
                ours(p).mul_scalar_checked(&U256::new(s.0)).unwrap(),
                expected,
            );
        }
    }
}

#[test]
fn checked_scalars_match_binary_oracle_and_reject_other_cosets() {
    let mut rng = StdRng::seed_from_u64(0x6732_5f63_686b_7631);
    let mut r_minus_1 = Fr::MODULUS;
    r_minus_1.0[0] -= 1;
    for _ in 0..64 {
        let p = on_curve(&mut rng);
        let torsion = p.mul_bigint(Fr::MODULUS).into_affine();
        let subgroup = p.mul_bigint(ark_bn254::g2::Config::COFACTOR).into_affine();
        assert!(!torsion.infinity);
        let scalar = BigInt(rng.random());
        check(
            ours(subgroup)
                .mul_scalar_checked(&U256::new(scalar.0))
                .unwrap(),
            subgroup.mul_bigint(scalar.0).into_affine(),
        );
        for nonmember in [p, torsion, (subgroup + torsion).into_affine()] {
            assert!(!nonmember.mul_bigint(Fr::MODULUS).into_affine().infinity);
            for s in [
                BigInt::from(0u64),
                BigInt::from(1u64),
                BigInt::from(2u64),
                Fr::MODULUS,
                r_minus_1,
                scalar,
                BigInt([u64::MAX; 4]),
            ] {
                assert_eq!(ours(nonmember).mul_scalar_checked(&U256::new(s.0)), None);
            }
            // Multiplication on the full twist must still retain the raw scalar.
            check(
                ours(nonmember).mul_scalar(&U256::new(Fr::MODULUS.0)),
                nonmember.mul_bigint(Fr::MODULUS).into_affine(),
            );
        }
    }
}
