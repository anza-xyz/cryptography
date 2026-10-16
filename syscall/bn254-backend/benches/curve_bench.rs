//! G1, G2 and pairing timings through the little-endian byte encodings.
//!
//! Each timed call decodes and validates its inputs, computes, and encodes the
//! result, as a syscall would. Benchmarks rotate through many inputs, so the
//! branch predictor cannot learn their data-dependent outcomes, which would
//! favor branchy code over branch-free code.

use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field as _, PrimeField};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254_backend::{backend::U256, g1, g2, pairing::try_multi_pairing};
use std::hint::black_box;

const GROUP_INPUTS: usize = 1024;
const PAIRING_INPUTS: usize = 32;
const PAIR_COUNTS: [usize; 3] = [1, 4, 16];

fn fq_bytes(value: Fq) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

fn g1_bytes(p: G1Affine) -> [u8; 64] {
    let mut bytes = [0; 64];
    if !p.infinity {
        bytes[..32].copy_from_slice(&fq_bytes(p.x));
        bytes[32..].copy_from_slice(&fq_bytes(p.y));
    }
    bytes
}

fn g2_bytes(q: G2Affine) -> [u8; 128] {
    let mut bytes = [0; 128];
    if !q.infinity {
        for (chunk, value) in bytes
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([q.x.c0, q.x.c1, q.y.c0, q.y.c1])
        {
            chunk.copy_from_slice(&fq_bytes(value));
        }
    }
    bytes
}

fn random_scalar(rng: &mut StdRng) -> Fr {
    Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>())
}

fn g1_point(scalar: Fr) -> G1Affine {
    (G1Affine::generator() * scalar).into_affine()
}

fn g2_point(scalar: Fr) -> G2Affine {
    (G2Affine::generator() * scalar).into_affine()
}

fn concat<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    parts.concat().try_into().unwrap()
}

fn raw_scalar(bytes: &[u8]) -> U256 {
    U256::new(core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[8 * i..8 * (i + 1)].try_into().unwrap())
    }))
}

#[inline(never)]
fn g1_add(input: &[u8; 128]) -> Option<[u8; 64]> {
    let a = g1::Affine::from_le_bytes(input[..64].try_into().unwrap())?;
    let b = g1::Affine::from_le_bytes(input[64..].try_into().unwrap())?;
    Some((a + b).to_le_bytes())
}

#[inline(never)]
fn g1_mul(input: &[u8; 96]) -> Option<[u8; 64]> {
    let p = g1::Affine::from_le_bytes(input[..64].try_into().unwrap())?;
    Some(p.mul_scalar(&raw_scalar(&input[64..])).to_le_bytes())
}

#[inline(never)]
fn g2_add(input: &[u8; 256]) -> Option<[u8; 128]> {
    let a = g2::Affine::from_le_bytes(input[..128].try_into().unwrap())?;
    let b = g2::Affine::from_le_bytes(input[128..].try_into().unwrap())?;
    Some((a + b).to_le_bytes())
}

#[inline(never)]
fn g2_mul(input: &[u8; 160]) -> Option<[u8; 128]> {
    let q = g2::Affine::from_le_bytes(input[..128].try_into().unwrap())?;
    Some(
        q.mul_scalar_checked(&raw_scalar(&input[128..]))?
            .to_le_bytes(),
    )
}

/// Decodes pairs lazily, so the call allocates nothing.
#[inline(never)]
fn pairing_is_one(input: &[u8]) -> Option<bool> {
    let pairs = input.as_chunks::<192>().0.iter().map(|pair| {
        let p = g1::Affine::from_le_bytes(pair[..64].try_into().unwrap()).ok_or(())?;
        let q = g2::Affine::from_le_bytes(pair[64..].try_into().unwrap()).ok_or(())?;
        Ok::<_, ()>((p, q))
    });
    try_multi_pairing(pairs)
        .ok()
        .map(|value| value.is_identity())
}

/// Times `call` over the inputs in turn, after checking every expected output.
fn bench_rotating<I, O: PartialEq + core::fmt::Debug>(
    c: &mut Criterion,
    name: &str,
    cases: &[(I, O)],
    call: fn(&I) -> O,
) {
    for (input, expected) in cases {
        assert_eq!(&call(input), expected, "{name} mismatch");
    }
    let mut index = 0;
    c.bench_function(name, |b| {
        b.iter(|| {
            let input = &cases[index].0;
            index = (index + 1) % cases.len();
            black_box(call(black_box(input)))
        })
    });
}

fn bench_groups(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x6375_7276_6562_656e);
    let mut g1_adds = Vec::new();
    let mut g1_muls = Vec::new();
    let mut g2_adds = Vec::new();
    let mut g2_muls = Vec::new();
    for _ in 0..GROUP_INPUTS {
        let [p, q] = [(); 2].map(|_| g1_point(random_scalar(&mut rng)));
        g1_adds.push((
            concat(&[&g1_bytes(p), &g1_bytes(q)]),
            Some(g1_bytes((p + q).into_affine())),
        ));
        let scalar = rng.random::<[u8; 32]>();
        let product = p.mul_bigint(raw_scalar(&scalar).0).into_affine();
        g1_muls.push((concat(&[&g1_bytes(p), &scalar]), Some(g1_bytes(product))));

        let [p, q] = [(); 2].map(|_| g2_point(random_scalar(&mut rng)));
        g2_adds.push((
            concat(&[&g2_bytes(p), &g2_bytes(q)]),
            Some(g2_bytes((p + q).into_affine())),
        ));
        let scalar = rng.random::<[u8; 32]>();
        let product = p.mul_bigint(raw_scalar(&scalar).0).into_affine();
        g2_muls.push((concat(&[&g2_bytes(p), &scalar]), Some(g2_bytes(product))));
    }
    bench_rotating(c, "g1_add", &g1_adds, g1_add);
    bench_rotating(c, "g1_mul", &g1_muls, g1_mul);
    bench_rotating(c, "g2_add", &g2_adds, g2_add);
    bench_rotating(c, "g2_mul", &g2_muls, g2_mul);
}

fn bench_pairings(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x7061_6972_6265_6e63);
    for count in PAIR_COUNTS {
        let cases: Vec<_> = (0..PAIRING_INPUTS)
            .map(|_| {
                let mut scalars: Vec<_> = (0..count)
                    .map(|_| [(); 2].map(|_| random_scalar(&mut rng)))
                    .collect();
                // Like a valid proof, a multi-pair product cancels to identity:
                // the last G1 scalar negates the other exponents' sum.
                if let Some(([last, b], rest)) = scalars.split_last_mut()
                    && !rest.is_empty()
                {
                    let sum: Fr = rest.iter().map(|[a, b]| *a * b).sum();
                    *last = -sum * b.inverse().unwrap();
                }
                let mut bytes = Vec::with_capacity(192 * count);
                for &[a, b] in &scalars {
                    bytes.extend(g1_bytes(g1_point(a)));
                    bytes.extend(g2_bytes(g2_point(b)));
                }
                (bytes, Some(count > 1))
            })
            .collect();
        bench_rotating(c, &format!("pairing_{count}"), &cases, |input| {
            pairing_is_one(input)
        });
    }
}

criterion_group!(benches, bench_groups, bench_pairings);
criterion_main!(benches);
