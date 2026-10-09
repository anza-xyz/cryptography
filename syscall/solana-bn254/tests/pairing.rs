use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq12 as ArkFq12, Fr as ArkFr, G1Affine, G2Affine,
};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInteger, Field as _, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Fq2, U256},
    g1, g2,
    gt::Gt,
    pairing::{PairingError, multi_pairing, pairing, pairing_product_is_one, try_multi_pairing},
};
use std::sync::LazyLock;

#[path = "fixtures/pairing.rs"]
mod fixtures;

static RADIX: LazyLock<ArkFq> = LazyLock::new(|| ArkFq::from(2).pow([256]));

fn raw(value: ArkFq) -> U256 {
    U256::new((value * *RADIX).into_bigint().0)
}

fn ours1(value: G1Affine) -> g1::Affine {
    if value.infinity {
        g1::Affine::IDENTITY
    } else {
        g1::Affine::from_montgomery(raw(value.x), raw(value.y)).unwrap()
    }
}

fn ours2(value: G2Affine) -> g2::Affine {
    let coefficient = |v: ArkFq2| Fq2::from_montgomery(raw(v.c0), raw(v.c1)).unwrap();
    if value.infinity {
        g2::Affine::IDENTITY
    } else {
        g2::Affine::from_montgomery(coefficient(value.x), coefficient(value.y)).unwrap()
    }
}

fn check(actual: Gt, expected: ArkFq12) {
    for (a, b) in actual
        .to_fq12()
        .to_coefficients()
        .into_iter()
        .zip([expected.c0, expected.c1])
    {
        for (a, b) in a.to_coefficients().into_iter().zip([b.c0, b.c1, b.c2]) {
            assert_eq!(a.to_montgomery(), (raw(b.c0), raw(b.c1)));
        }
    }
}

#[test]
fn generator_identity_and_signs_match_arkworks() {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let expected = Bn254::pairing(p, q).0;
    let actual = pairing(&ours1(p), &ours2(q)).unwrap();
    assert!(!actual.is_identity());
    check(actual, expected);
    for (p, q) in [
        (-p, q),
        (p, -q),
        (-p, -q),
        (G1Affine::identity(), q),
        (p, G2Affine::identity()),
        (G1Affine::identity(), G2Affine::identity()),
    ] {
        check(
            pairing(&ours1(p), &ours2(q)).unwrap(),
            Bn254::pairing(p, q).0,
        );
    }
    assert_eq!(pairing(&ours1(-p), &ours2(q)), Some(actual.inverse()));
    assert_eq!(
        multi_pairing(core::iter::empty::<(g1::Affine, g2::Affine)>()),
        Some(Gt::IDENTITY)
    );
    assert_eq!(
        multi_pairing(core::iter::from_fn(|| None::<(g1::Affine, g2::Affine)>)),
        Some(Gt::IDENTITY)
    );
    assert_eq!(
        pairing_product_is_one(core::iter::empty::<(g1::Affine, g2::Affine)>()),
        Some(true)
    );
}

#[test]
fn seeded_pairings_and_bilinearity_match_exact_values() {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let base = pairing(&ours1(p), &ours2(q)).unwrap();
    let mut rng = StdRng::seed_from_u64(0x7061_6972_7365_7631);
    for _ in 0..64 {
        let a = rng.random::<[u64; 4]>();
        let b = rng.random::<[u64; 4]>();
        let pa = p.mul_bigint(a).into_affine();
        let qb = q.mul_bigint(b).into_affine();
        let actual = pairing(&ours1(pa), &ours2(qb)).unwrap();
        check(actual, Bn254::pairing(pa, qb).0);
        let a = ArkFr::from_le_bytes_mod_order(&ark_ff::BigInt(a).to_bytes_le());
        let b = ArkFr::from_le_bytes_mod_order(&ark_ff::BigInt(b).to_bytes_le());
        assert_eq!(actual, base.pow(&U256::new((a * b).into_bigint().0)));
    }
}

#[test]
fn multi_pairing_matches_singles_across_batch_boundaries() {
    let mut rng = StdRng::seed_from_u64(0x7061_6972_6d75_7631);
    let reference: Vec<_> = (0..65)
        .map(|_| {
            (
                G1Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
                G2Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            )
        })
        .collect();
    let pairs: Vec<_> = reference
        .iter()
        .map(|&(p, q)| (ours1(p), ours2(q)))
        .collect();
    let singles: Vec<_> = pairs.iter().map(|(p, q)| pairing(p, q).unwrap()).collect();
    for count in [0, 1, 2, 3, 4, 8, 15, 16, 17, 31, 32, 33, 48, 49, 63, 64, 65] {
        let actual = multi_pairing(pairs[..count].iter().map(|(p, q)| (p, q))).unwrap();
        let expected = Bn254::multi_pairing(
            reference[..count].iter().map(|p| p.0),
            reference[..count].iter().map(|p| p.1),
        )
        .0;
        check(actual, expected);
        assert_eq!(multi_pairing(pairs[..count].iter().copied()), Some(actual));
        assert_eq!(
            try_multi_pairing(pairs[..count].iter().copied().map(Ok::<_, ()>)),
            Ok(actual)
        );
        assert_eq!(
            try_multi_pairing(pairs[..count].iter().map(|(p, q)| Ok::<_, ()>((p, q)))),
            Ok(actual)
        );
        assert_eq!(
            actual,
            singles[..count]
                .iter()
                .copied()
                .fold(Gt::IDENTITY, |a, b| a * b)
        );
        assert_eq!(
            pairing_product_is_one(pairs[..count].iter().map(|(p, q)| (p, q))),
            Some(actual.is_identity())
        );
    }
}

#[test]
fn identities_and_cancellation_span_batches() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    for count in [15, 16, 17, 31, 32, 33, 63, 64, 65] {
        let mut pairs = vec![(p, q); count];
        // Cancellation partners deliberately fall in subsequent batches.
        pairs.extend(vec![(-p, q); count]);
        pairs.insert(0, (g1::Affine::IDENTITY, q));
        for position in [16, 32, 64] {
            if position <= pairs.len() {
                pairs.insert(position, (p, g2::Affine::IDENTITY));
            }
        }
        pairs.push((g1::Affine::IDENTITY, g2::Affine::IDENTITY));
        assert_eq!(
            multi_pairing(pairs.iter().map(|(p, q)| (p, q))),
            Some(Gt::IDENTITY)
        );
        assert_eq!(
            pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))),
            Some(true)
        );
    }
}

fn non_subgroup() -> G2Affine {
    for i in 0..1024u64 {
        if let Some(point) =
            G2Affine::get_point_from_x_unchecked(ArkFq2::new(ArkFq::from(i), ArkFq::ONE), false)
        {
            let torsion = point.mul_bigint(ArkFr::MODULUS).into_affine();
            if !torsion.infinity {
                assert!(!torsion.mul_bigint(ArkFr::MODULUS).into_affine().infinity);
                return torsion;
            }
        }
    }
    panic!("no non-subgroup fixture");
}

#[test]
fn nonmembers_are_rejected_despite_identity_or_cancelling_prefixes() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    let torsion = non_subgroup();
    for bad in [
        torsion,
        (torsion.into_group() + G2Affine::generator()).into_affine(),
    ] {
        assert!(!bad.mul_bigint(ArkFr::MODULUS).into_affine().infinity);
        let bad = ours2(bad);
        for p_bad in [p, g1::Affine::IDENTITY] {
            assert_eq!(pairing(&p_bad, &bad), None);
            for count in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
                for position in [0, count / 2, count] {
                    let mut pairs: Vec<_> = (0..count)
                        .map(|i| (if i % 2 == 0 { p } else { -p }, q))
                        .collect();
                    pairs.insert(position, (p_bad, bad));
                    // Hide the iterator's length: the first pair and later
                    // invalid points must still pass through validation.
                    let mut inputs = pairs.iter().map(|(p, q)| (p, q));
                    assert_eq!(multi_pairing(core::iter::from_fn(|| inputs.next())), None);
                    assert_eq!(multi_pairing(pairs.iter().copied()), None);
                    assert_eq!(
                        pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))),
                        None
                    );
                }
            }
        }
    }
}

#[test]
fn fallible_pairing_propagates_errors_after_valid_prefixes() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    for count in [0, 1, 2, 31, 32, 33, 64, 65] {
        for pattern in 0..3 {
            let prefix: Vec<_> = (0..count)
                .map(|i| match pattern {
                    0 => (g1::Affine::IDENTITY, q),
                    1 => (p, q),
                    _ => (if i % 2 == 0 { p } else { -p }, q),
                })
                .collect();
            let owned = prefix.iter().copied().map(Ok);
            let borrowed = prefix.iter().map(|(p, q)| Ok((p, q)));
            // A non-Copy error is preserved. Neither iterator may advance
            // beyond it, including after a complete nonidentity batch.
            assert_eq!(
                try_multi_pairing(
                    owned
                        .chain(core::iter::once(Err(String::from("decode failure"))))
                        .chain(core::iter::once_with(|| panic!("read after error")))
                ),
                Err(PairingError::Input(String::from("decode failure")))
            );
            assert_eq!(
                try_multi_pairing(
                    borrowed
                        .chain(core::iter::once(Err(String::from("decode failure"))))
                        .chain(core::iter::once_with(|| panic!("read after error")))
                ),
                Err(PairingError::Input(String::from("decode failure")))
            );
        }
    }
}

#[test]
fn fallible_pairing_reports_the_first_input_or_subgroup_error() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    let bad = ours2(non_subgroup());
    for p_bad in [p, g1::Affine::IDENTITY] {
        // Distinguish a subgroup failure from an input failure, even when
        // the one-item read-ahead has already yielded the latter.
        assert_eq!(
            try_multi_pairing([Ok((p_bad, bad)), Err("decode failure")]),
            Err(PairingError::InvalidG2)
        );
        assert_eq!(
            try_multi_pairing([Err("decode failure"), Ok((p_bad, bad))]),
            Err(PairingError::Input("decode failure"))
        );
        for count in [0, 1, 2, 31, 32, 33] {
            let prefix = (0..count).map(|i| Ok((if i % 2 == 0 { p } else { -p }, q)));
            assert_eq!(
                try_multi_pairing(
                    prefix
                        .chain(core::iter::once(Ok::<_, ()>((p_bad, bad))))
                        // A first-pair validation failure permits one read-ahead.
                        .chain(core::iter::once(Ok((p, q))))
                        .chain(core::iter::once_with(|| panic!("read after invalid G2")))
                ),
                Err(PairingError::InvalidG2)
            );
        }
    }
}

#[test]
fn pairing_errors_support_display_and_error_chaining() {
    use core::{convert::Infallible, error::Error, num::ParseIntError};

    // Display remains available when the input type is not an Error.
    let message = String::from("truncated pair");
    assert_eq!(
        PairingError::Input(message.as_str()).to_string(),
        "pairing input error: truncated pair"
    );

    let input = "invalid".parse::<u8>().unwrap_err();
    let error = PairingError::Input(input.clone());
    assert_eq!(error.to_string(), format!("pairing input error: {input}"));
    let source = error.source().unwrap();
    assert_eq!(source.downcast_ref::<ParseIntError>(), Some(&input));
    assert!(source.source().is_none());

    let error = PairingError::<Infallible>::InvalidG2;
    assert_eq!(
        error.to_string(),
        "G2 point is not in the prime-order subgroup"
    );
    assert!(error.source().is_none());
}

fn decode(input: &[u8], big_endian: bool) -> Option<Vec<(g1::Affine, g2::Affine)>> {
    if !input.len().is_multiple_of(192) {
        return None;
    }
    input
        .as_chunks::<192>()
        .0
        .iter()
        .map(|bytes| {
            let p = &bytes[..64].try_into().unwrap();
            let q = &bytes[64..].try_into().unwrap();
            Some(if big_endian {
                (g1::Affine::from_be_bytes(p)?, g2::Affine::from_be_bytes(q)?)
            } else {
                (g1::Affine::from_le_bytes(p)?, g2::Affine::from_le_bytes(q)?)
            })
        })
        .collect()
}

#[test]
fn saved_byte_fixtures_match_the_pairing_engine_in_both_endiannesses() {
    for fixture in fixtures::fixtures() {
        for (be, bytes) in [(false, &fixture.le), (true, &fixture.be)] {
            // Decoding intentionally does not check G2 subgroup membership:
            // the production pairing boundary must reject those fixtures.
            let actual = decode(bytes, be)
                .and_then(|pairs| pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))));
            assert_eq!(actual, fixture.expected, "{} be={be}", fixture.name);
            assert_eq!(
                streaming_pairing(bytes, be),
                actual,
                "streamed {} be={be}",
                fixture.name
            );
        }
    }
}

// The adapter reports malformed coordinates and incomplete trailing pairs as
// iterator errors. The library propagates them without a caller-side flag.
fn streaming_pairing(input: &[u8], big_endian: bool) -> Option<bool> {
    let pairs = input.chunks(192).map(|bytes| -> Result<_, &'static str> {
        let bytes: &[u8; 192] = bytes.try_into().map_err(|_| "truncated pair")?;
        let p = bytes[..64].try_into().unwrap();
        let q = bytes[64..].try_into().unwrap();
        let (p, q) = if big_endian {
            (g1::Affine::from_be_bytes(p), g2::Affine::from_be_bytes(q))
        } else {
            (g1::Affine::from_le_bytes(p), g2::Affine::from_le_bytes(q))
        };
        Ok((
            p.ok_or("invalid G1 encoding")?,
            q.ok_or("invalid G2 encoding")?,
        ))
    });
    try_multi_pairing(pairs)
        .ok()
        .map(|value| value.is_identity())
}

#[test]
fn streaming_decoder_rejects_malformed_and_truncated_pairs() {
    // Valid identity prefixes on either side of the active batch boundary.
    for count in [0, 1, 31, 32, 33] {
        for trailing_len in [1, 63, 64, 191] {
            let bytes = vec![0; count * 192 + trailing_len];
            for be in [false, true] {
                assert_eq!(streaming_pairing(&bytes, be), None);
            }
        }
        let mut bytes = vec![0; count * 192];
        bytes.extend([0xff; 192]);
        bytes.extend([0; 192]);
        for be in [false, true] {
            assert_eq!(streaming_pairing(&bytes, be), None);
        }
    }
}
