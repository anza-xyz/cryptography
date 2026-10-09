//! Deterministic byte fixtures for pairing and decoding-contract tests.
//! Inputs and expectations are generated independently with Arkworks.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};

pub struct Fixture {
    pub name: String,
    pub le: Vec<u8>,
    pub be: Vec<u8>,
    pub expected: Option<bool>,
}

fn g1_bytes(point: G1Affine) -> [u8; 64] {
    let mut out = [0; 64];
    if !point.infinity {
        out[..32].copy_from_slice(&point.x.into_bigint().to_bytes_le());
        out[32..].copy_from_slice(&point.y.into_bigint().to_bytes_le());
    }
    out
}

fn g2_bytes(point: G2Affine) -> [u8; 128] {
    let mut out = [0; 128];
    if !point.infinity {
        for (value, chunk) in [point.x.c0, point.x.c1, point.y.c0, point.y.c1]
            .into_iter()
            .zip(out.as_chunks_mut::<32>().0)
        {
            chunk.copy_from_slice(&value.into_bigint().to_bytes_le());
        }
    }
    out
}

fn pair(p: G1Affine, q: G2Affine) -> Vec<u8> {
    [g1_bytes(p).as_slice(), g2_bytes(q).as_slice()].concat()
}

fn fixture(name: impl Into<String>, le: Vec<u8>, expected: Option<bool>) -> Fixture {
    let mut be = le.clone();
    for chunk in be.as_chunks_mut::<192>().0 {
        chunk[..32].reverse();
        chunk[32..64].reverse();
        // Reversing an Fq2 coordinate changes both limb byte order and c0/c1 order.
        chunk[64..128].reverse();
        chunk[128..192].reverse();
    }
    Fixture {
        name: name.into(),
        le,
        be,
        expected,
    }
}

fn non_subgroup_point() -> G2Affine {
    // Deterministic arbitrary twist point; multiplying by r extracts torsion.
    for i in 0..1024u64 {
        if let Some(point) =
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::ONE), false)
        {
            let torsion = point.mul_bigint(Fr::MODULUS).into_affine();
            if !torsion.infinity {
                assert!(!torsion.mul_bigint(Fr::MODULUS).into_affine().infinity);
                return torsion;
            }
        }
    }
    panic!("no non-subgroup fixture found");
}

pub fn fixtures() -> Vec<Fixture> {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let zero1 = G1Affine::identity();
    let zero2 = G2Affine::identity();
    let single = pair(p, q);
    let cancel = [single.clone(), pair(-p, q)].concat();
    let mut cases = vec![
        fixture("empty", vec![], Some(true)),
        fixture("generator", single.clone(), Some(false)),
        fixture("cancelling", cancel.clone(), Some(true)),
        fixture(
            "weighted_cancelling",
            [
                pair(
                    p.mul_bigint([2]).into_affine(),
                    q.mul_bigint([3]).into_affine(),
                ),
                pair(-p.mul_bigint([6]).into_affine(), q),
            ]
            .concat(),
            Some(true),
        ),
        fixture("g1_infinity", pair(zero1, q), Some(true)),
        fixture("g2_infinity", pair(p, zero2), Some(true)),
        fixture("both_infinity", pair(zero1, zero2), Some(true)),
        fixture(
            "identity_and_cancelling",
            [pair(zero1, q), cancel.clone(), pair(p, zero2)].concat(),
            Some(true),
        ),
    ];
    for count in [2, 3, 4, 8, 15, 16, 17, 32] {
        cases.push(fixture(
            format!("repeated_{count}"),
            single.repeat(count),
            Some(false),
        ));
    }
    for length in [1, 191, 193, 383] {
        cases.push(fixture(
            format!("invalid_length_{length}"),
            vec![0; length],
            None,
        ));
    }
    for (name, offset) in [
        ("g1_x", 0),
        ("g1_y", 32),
        ("g2_x_c0", 64),
        ("g2_x_c1", 96),
        ("g2_y_c0", 128),
        ("g2_y_c1", 160),
    ] {
        let mut bytes = single.clone();
        bytes[offset..offset + 32].copy_from_slice(&Fq::MODULUS.to_bytes_le());
        cases.push(fixture(format!("noncanonical_{name}"), bytes, None));
    }
    for (name, flag_byte) in [("g1", 63), ("g2", 191)] {
        for (flag_name, flag, expected) in [
            ("sign", 0x80, Some(false)),
            ("infinity", 0x40, Some(true)),
            ("invalid_flags", 0xc0, None),
        ] {
            let mut bytes = single.clone();
            bytes[flag_byte] |= flag;
            cases.push(fixture(format!("{name}_{flag_name}"), bytes, expected));
        }
    }
    let mut off_curve_g1 = single.clone();
    off_curve_g1[32..64].fill(0);
    cases.push(fixture("off_curve_g1", off_curve_g1, None));
    let mut off_curve_g2 = single.clone();
    off_curve_g2[128..192].fill(0);
    cases.push(fixture("off_curve_g2", off_curve_g2, None));
    let nonmember = non_subgroup_point();
    cases.push(fixture("non_subgroup", pair(p, nonmember), None));
    cases.push(fixture(
        "infinity_with_non_subgroup",
        pair(zero1, nonmember),
        None,
    ));
    cases.push(fixture(
        "cancelling_then_non_subgroup",
        [cancel.clone(), pair(p, nonmember)].concat(),
        None,
    ));
    let mut noncanonical_identity = single;
    noncanonical_identity[0..32].copy_from_slice(&Fq::MODULUS.to_bytes_le());
    noncanonical_identity[63] |= 0x40;
    cases.push(fixture(
        "noncanonical_flagged_identity",
        noncanonical_identity,
        None,
    ));
    let mut trailing_byte = cancel;
    trailing_byte.push(0);
    cases.push(fixture(
        "cancelling_then_trailing_byte",
        trailing_byte,
        None,
    ));
    cases
}
