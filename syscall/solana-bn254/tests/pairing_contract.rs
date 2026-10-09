//! Independent checks of the pairing convention and input decoding contract.
//! Production pairing results are exercised separately in tests/pairing.rs.

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq12 as ArkFq12, Fr as ArkFr, G1Affine, G2Affine,
};
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{MillerLoopOutput, Pairing},
};
use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Fq12, U256},
    g1, g2,
};

#[path = "fixtures/pairing.rs"]
mod fixtures;
#[path = "common/tower.rs"]
mod tower;
use tower::*;

fn generic_pow(mut value: Fq12, exponent: &BigUint) -> Fq12 {
    let mut result = Fq12::ONE;
    for limb in exponent.to_u64_digits() {
        for bit in 0..64 {
            if limb >> bit & 1 != 0 {
                result = result * value;
            }
            value = value.square();
        }
    }
    result
}

#[test]
fn final_exponent_convention_matches_arkworks_exactly() {
    let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
    let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
    let x = BigUint::from(4965661367192848881u64);
    let c = 2u8 * &x * (6u8 * x.pow(2) + 3u8 * &x + 1u8);
    assert!(c > BigUint::from(1u8) && c < r);
    let cyclotomic_order = q.pow(4) - q.pow(2) + 1u8;
    assert_eq!(&cyclotomic_order % &r, BigUint::from(0u8));
    let chain = q.pow(3) * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 4u8 * &x - 1u8)
        + q.pow(2) * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 6u8 * &x)
        + &q * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 4u8 * &x)
        + (12u8 * x.pow(3) + 12u8 * x.pow(2) + 6u8 * &x + 1u8);
    assert_eq!(chain, &c * (&cyclotomic_order / &r));
    let unscaled = (q.pow(12) - 1u8) / &r;
    let exponent = &unscaled * &c;

    let mut rng = StdRng::seed_from_u64(0x7061_6972_5f66_6531);
    for input in [ArkFq12::ONE, random12(&mut rng), random12(&mut rng)] {
        let expected = Bn254::final_exponentiation(MillerLoopOutput(input))
            .unwrap()
            .0;
        // The expected answer is arkworks' optimized chain. The actual answer
        // uses only the new generic field multiplication/square and integer c*E.
        check12(generic_pow(ours12(input), &exponent), expected);
        assert_eq!(expected.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
        assert_eq!(
            input.pow(unscaled.to_u64_digits()).pow(c.to_u64_digits()),
            expected
        );
    }
    assert_eq!(
        Bn254::final_exponentiation(MillerLoopOutput(ArkFq12::ZERO)),
        None
    );
}

fn decode_with_curve_apis(input: &[u8], big_endian: bool) -> Option<Vec<(G1Affine, G2Affine)>> {
    if !input.len().is_multiple_of(192) {
        return None;
    }
    let r_inverse = ArkFq::from(2u64).pow([256]).inverse().unwrap();
    let fq = |value: U256| ArkFq::from_bigint(ark_ff::BigInt(value.0)).unwrap() * r_inverse;
    let mut pairs = Vec::new();
    for bytes in input.as_chunks::<192>().0 {
        let p_bytes: &[u8; 64] = bytes[..64].try_into().unwrap();
        let q_bytes: &[u8; 128] = bytes[64..].try_into().unwrap();
        let p = if big_endian {
            g1::Affine::from_be_bytes(p_bytes)
        } else {
            g1::Affine::from_le_bytes(p_bytes)
        }?;
        let q = if big_endian {
            g2::Affine::from_be_bytes(q_bytes)
        } else {
            g2::Affine::from_le_bytes(q_bytes)
        }?;
        if !q.is_in_correct_subgroup() {
            return None;
        }
        let p = if p.is_identity() {
            G1Affine::identity()
        } else {
            let (x, y) = p.to_montgomery();
            G1Affine::new_unchecked(fq(x), fq(y))
        };
        let q = if q.is_identity() {
            G2Affine::identity()
        } else {
            let (x, y) = q.to_montgomery();
            let (x0, x1) = x.to_montgomery();
            let (y0, y1) = y.to_montgomery();
            G2Affine::new_unchecked(ArkFq2::new(fq(x0), fq(x1)), ArkFq2::new(fq(y0), fq(y1)))
        };
        // Independent binary order multiplication checks the fixture's trust boundary.
        assert!(q.mul_bigint(ArkFr::MODULUS).into_affine().infinity);
        pairs.push((p, q));
    }
    Some(pairs)
}

#[test]
fn byte_fixtures_preserve_decoding_and_validation() {
    for fixture in fixtures::fixtures() {
        for (big_endian, input) in [(false, &fixture.le), (true, &fixture.be)] {
            let decoded = decode_with_curve_apis(input, big_endian);
            assert_eq!(
                decoded.is_some(),
                fixture.expected.is_some(),
                "{} be={big_endian}",
                fixture.name
            );
            if let Some(pairs) = decoded {
                let value =
                    Bn254::multi_pairing(pairs.iter().map(|p| p.0), pairs.iter().map(|p| p.1)).0;
                assert_eq!(
                    Some(value == ArkFq12::ONE),
                    fixture.expected,
                    "{} be={big_endian}",
                    fixture.name
                );
                // The production pairing tests use these same fixtures.
                check12(ours12(value), value);
            }
        }
    }
}
