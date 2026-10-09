use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, Fr as ArkFr, G1Affine,
    G2Affine,
};
use ark_ec::{
    AffineRepr,
    pairing::{MillerLoopOutput, Pairing},
};
use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
use num_bigint::BigUint;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Field, Fq12, Fr, U256},
    gt::Gt,
};

#[path = "common/tower.rs"]
mod tower;
use tower::*;

fn generator() -> ArkFq12 {
    let value = Bn254::pairing(G1Affine::generator(), G2Affine::generator()).0;
    assert_ne!(value, ArkFq12::ONE);
    assert_eq!(value.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
    value
}

fn integer(value: &BigUint) -> U256 {
    assert!(value.bits() <= 256);
    let mut limbs = [0; 4];
    let digits = value.to_u64_digits();
    limbs[..digits.len()].copy_from_slice(&digits);
    U256::new(limbs)
}

fn check_membership(value: ArkFq12) {
    let expected = value != ArkFq12::ZERO && value.pow(ArkFr::MODULUS.0) == ArkFq12::ONE;
    let actual = Gt::from_fq12(ours12(value));
    assert_eq!(actual.is_some(), expected);
    if let Some(actual) = actual {
        check12(actual.to_fq12(), value);
    }
}

fn check_pow(actual: Gt, expected: ArkFq12, exponent: &U256) {
    // The oracle consumes the raw integer limbs without converting through Fr.
    check12(actual.pow(exponent).to_fq12(), expected.pow(exponent.0));
}

#[test]
fn identity_is_field_one_and_zero_is_rejected() {
    assert_eq!(Fr::MODULUS.0, ArkFr::MODULUS.0);
    assert_eq!(Gt::default(), Gt::IDENTITY);
    assert_eq!(Gt::from_fq12(Fq12::ONE), Some(Gt::IDENTITY));
    assert_eq!(Gt::from_fq12(Fq12::ZERO), None);
    assert_eq!(Gt::from_fq12(Fq12::default()), None);
    assert!(Gt::IDENTITY.is_identity());
    assert_eq!(Gt::IDENTITY.to_fq12(), Fq12::ONE);
    assert_eq!(Gt::IDENTITY.square(), Gt::IDENTITY);
    assert_eq!(Gt::IDENTITY.inverse(), Gt::IDENTITY);
    assert_eq!(Gt::IDENTITY * Gt::IDENTITY, Gt::IDENTITY);
    for exponent in [
        U256::zero(),
        U256::one(),
        Fr::MODULUS,
        U256::new([u64::MAX; 4]),
    ] {
        assert_eq!(Gt::IDENTITY.pow(&exponent), Gt::IDENTITY);
    }
}

#[test]
fn checked_construction_matches_independent_order_test() {
    let two = ArkFq12::new(
        ArkFq6::new(
            ArkFq2::new(ArkFq::from(2), ArkFq::ZERO),
            ArkFq2::ZERO,
            ArkFq2::ZERO,
        ),
        ArkFq6::ZERO,
    );
    for value in [ArkFq12::ZERO, ArkFq12::ONE, -ArkFq12::ONE, two, generator()] {
        check_membership(value);
    }
    // Isolate each Fq basis coefficient, including nonmembers in subfields.
    for index in 0..12 {
        let mut coefficients = [ArkFq::ZERO; 12];
        coefficients[index] = ArkFq::ONE;
        let pairs = core::array::from_fn::<_, 6, _>(|i| {
            ArkFq2::new(coefficients[2 * i], coefficients[2 * i + 1])
        });
        let value = ArkFq12::new(
            ArkFq6::new(pairs[0], pairs[1], pairs[2]),
            ArkFq6::new(pairs[3], pairs[4], pairs[5]),
        );
        check_membership(value);
        check_membership(-value);
    }
    let mut rng = StdRng::seed_from_u64(0x6774_5f63_686b_7631);
    for _ in 0..128 {
        check_membership(random12(&mut rng));
    }
}

#[test]
fn norm_one_and_cyclotomic_membership_do_not_suffice() {
    let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
    let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
    let cyclotomic_order = q.pow(4) - q.pow(2) + 1u8;
    // These integer identities justify conjugation-as-inverse for Gt.
    assert_eq!(&cyclotomic_order % &r, BigUint::from(0u8));
    assert_eq!((q.pow(2) + 1u8) * &cyclotomic_order, q.pow(6) + 1u8);
    assert_eq!((q.pow(6) + 1u8) % &r, BigUint::from(0u8));
    assert!(cyclotomic_order > r);

    let negative_one = -ArkFq12::ONE;
    assert_eq!(negative_one * negative_one, ArkFq12::ONE);
    assert_eq!(Gt::from_fq12(ours12(negative_one)), None);

    let easy_exponent = (q.pow(6) - 1u8) * (q.pow(2) + 1u8);
    let mut rng = StdRng::seed_from_u64(0x6774_5f6e_6f72_6d31);
    for _ in 0..16 {
        let input = random12(&mut rng);
        let conjugate = ArkFq12::new(input.c0, -input.c1);
        let norm_one = conjugate * input.inverse().unwrap();
        assert_eq!(
            norm_one * ArkFq12::new(norm_one.c0, -norm_one.c1),
            ArkFq12::ONE
        );
        assert_ne!(norm_one.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
        assert_eq!(Gt::from_fq12(ours12(norm_one)), None);

        let cyclotomic = input.pow(easy_exponent.to_u64_digits());
        assert_eq!(
            cyclotomic.pow(cyclotomic_order.to_u64_digits()),
            ArkFq12::ONE
        );
        assert_ne!(cyclotomic.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
        assert_eq!(Gt::from_fq12(ours12(cyclotomic)), None);
    }
}

#[test]
fn independent_final_exponent_outputs_are_accepted() {
    let mut rng = StdRng::seed_from_u64(0x6774_5f66_6578_7031);
    for _ in 0..32 {
        let expected = Bn254::final_exponentiation(MillerLoopOutput(random12(&mut rng)))
            .unwrap()
            .0;
        assert_eq!(expected.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
        let actual = Gt::from_fq12(ours12(expected)).unwrap();
        check12(actual.to_fq12(), expected);
        assert_eq!(actual.is_identity(), expected == ArkFq12::ONE);
        assert_eq!(actual.pow(&Fr::MODULUS), Gt::IDENTITY);
    }
}

#[test]
fn products_squares_and_inverses_match_arkworks() {
    let base = generator();
    let g = Gt::from_fq12(ours12(base)).unwrap();
    assert!(!g.is_identity());
    let mut rng = StdRng::seed_from_u64(0x6774_5f6f_7073_7631);
    for _ in 0..64 {
        let a = base.pow(rng.random::<[u64; 4]>());
        let b = base.pow(rng.random::<[u64; 4]>());
        let x = Gt::from_fq12(ours12(a)).unwrap();
        let y = Gt::from_fq12(ours12(b)).unwrap();
        check12((x * y).to_fq12(), a * b);
        check12(x.square().to_fq12(), a.square());
        check12(x.inverse().to_fq12(), a.inverse().unwrap());
        assert_eq!(x * Gt::IDENTITY, x);
        assert_eq!(Gt::IDENTITY * x, x);
        assert_eq!(x * x.inverse(), Gt::IDENTITY);
        assert_eq!(x.inverse().inverse(), x);
        assert_eq!(x * y, y * x);
        assert_eq!((x * y) * g, x * (y * g));
        assert_eq!((x * y).inverse(), x.inverse() * y.inverse());
        assert_eq!(Gt::from_fq12((x * y).to_fq12()), Some(x * y));
    }
}

#[test]
fn powers_accept_raw_integer_boundaries() {
    let expected = generator();
    let actual = Gt::from_fq12(ours12(expected)).unwrap();
    let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
    let one = BigUint::from(1u8);
    let limit = &one << 256usize;
    let mut exponents = vec![
        U256::zero(),
        U256::one(),
        U256::new([2, 0, 0, 0]),
        U256::new([u64::MAX; 4]),
    ];
    // Every bit, especially bit 255, must be treated as part of a raw integer.
    for bit in 0..256 {
        exponents.push(integer(&(&one << bit)));
    }
    for bit in [64, 128, 192, 255] {
        let power = &one << bit;
        exponents.push(integer(&(&power - &one)));
        exponents.push(integer(&(power + &one)));
    }
    for multiple in 1..=5u8 {
        let center = &r * multiple;
        assert!(&center + &one < limit);
        exponents.extend([
            integer(&(&center - &one)),
            integer(&center),
            integer(&(center + &one)),
        ]);
    }
    for exponent in exponents {
        check_pow(actual, expected, &exponent);
    }
    assert_eq!(actual.pow(&U256::zero()), Gt::IDENTITY);
    assert_eq!(actual.pow(&U256::one()), actual);
    assert_eq!(actual.pow(&integer(&(&r - &one))), actual.inverse());
    assert_eq!(actual.pow(&integer(&r)), Gt::IDENTITY);
    assert_eq!(actual.pow(&integer(&(r + one))), actual);
}

#[test]
fn seeded_powers_and_dependent_chains_match_arkworks() {
    let base = generator();
    let mut rng = StdRng::seed_from_u64(0x6774_5f63_686e_7631);
    for _ in 0..64 {
        let expected = base.pow(rng.random::<[u64; 4]>());
        let actual = Gt::from_fq12(ours12(expected)).unwrap();
        check_pow(actual, expected, &U256::new(rng.random()));
    }
    for _ in 0..16 {
        let mut expected = base.pow(rng.random::<[u64; 4]>());
        let mut actual = Gt::from_fq12(ours12(expected)).unwrap();
        let factor = base.pow(rng.random::<[u64; 4]>());
        let multiplier = Gt::from_fq12(ours12(factor)).unwrap();
        for step in 0..32u64 {
            match step % 4 {
                0 => {
                    actual = actual * multiplier;
                    expected *= factor;
                }
                1 => {
                    actual = actual.square();
                    expected.square_in_place();
                }
                2 => {
                    actual = actual.inverse();
                    expected = expected.inverse().unwrap();
                }
                _ => {
                    let exponent = U256::new([step + 1, 0, 0, 0]);
                    actual = actual.pow(&exponent);
                    expected = expected.pow(exponent.0);
                }
            }
            check12(actual.to_fq12(), expected);
        }
        assert_eq!(actual.pow(&Fr::MODULUS), Gt::IDENTITY);
        assert_eq!(Gt::from_fq12(actual.to_fq12()), Some(actual));
    }
}

#[test]
fn small_and_cross_limb_window_patterns_match_arkworks() {
    let base = generator();
    for expected in [base, base.inverse().unwrap()] {
        let actual = Gt::from_fq12(ours12(expected)).unwrap();
        for exponent in 0..=64 {
            check_pow(actual, expected, &U256::new([exponent, 0, 0, 0]));
        }
        for shift in [
            0, 1, 2, 3, 60, 61, 62, 63, 64, 65, 124, 125, 126, 127, 128, 129, 188, 189, 190, 191,
            192, 193, 252, 253,
        ] {
            for digit in [3u8, 5, 7] {
                let high = BigUint::from(digit) << shift;
                check_pow(actual, expected, &integer(&high));
                // Dense low bits exercise table use together with a window
                // that crosses a limb boundary; all bits remain ordinary integers.
                let dense = &high | BigUint::from(u32::MAX);
                check_pow(actual, expected, &integer(&dense));
            }
        }
    }
}
