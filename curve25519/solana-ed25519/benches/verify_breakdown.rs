//! Component-level breakdown of a single Ed25519 verification.
//!
//! Splits `VerificationKey::verify` into the SHA-512 challenge hash and the
//! curve arithmetic that follows it.
#![allow(non_snake_case)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sha2::{Digest, Sha512};

use solana_ed25519::ed_sigs::*;
use solana_ed25519::edwards::{CompressedEdwardsY, EdwardsPoint};
use solana_ed25519::scalar::Scalar;
use solana_ed25519::traits::{HEEADecomposition, IsIdentity};

/// Message sizes: empty, a 32-byte digest, and a 1232-byte Solana packet.
static MSG_SIZES: [usize; 4] = [0, 32, 256, 1232];

fn inputs(msg_len: usize) -> (VerificationKey, Signature, Vec<u8>) {
    let sk = SigningKey::from([7u8; 32]);
    let vk = VerificationKey::from(&sk);
    let msg = vec![0xABu8; msg_len];
    let sig = sk.sign(&msg);
    (vk, sig, msg)
}

/// The exact hash `challenge_scalar` performs: SHA-512(R || A || msg).
fn challenge_scalar(vk_bytes: &[u8; 32], sig: &Signature, msg: &[u8]) -> Scalar {
    let mut h = Sha512::default();
    h.update(&sig.r_bytes()[..]);
    h.update(&vk_bytes[..]);
    h.update(msg);
    let out = h.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(out.as_slice());
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Hash only, no scalar reduction.
fn hash_only(vk_bytes: &[u8; 32], sig: &Signature, msg: &[u8]) {
    let mut h = Sha512::default();
    h.update(&sig.r_bytes()[..]);
    h.update(&vk_bytes[..]);
    h.update(msg);
    let _ = h.finalize();
}

fn bench_hash_vs_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify breakdown");

    for &n in MSG_SIZES.iter() {
        let (vk, sig, msg) = inputs(n);
        let vk_bytes: [u8; 32] = vk.into();

        group.bench_with_input(BenchmarkId::new("1. sha512 only", n), &n, |b, _| {
            b.iter(|| hash_only(&vk_bytes, &sig, &msg))
        });

        group.bench_with_input(BenchmarkId::new("2. challenge scalar", n), &n, |b, _| {
            b.iter(|| challenge_scalar(&vk_bytes, &sig, &msg))
        });

        group.bench_with_input(BenchmarkId::new("3. verify_zebra (full)", n), &n, |b, _| {
            b.iter(|| vk.verify_zebra(&sig, &msg))
        });

        group.bench_with_input(BenchmarkId::new("4. verify_dalek (full)", n), &n, |b, _| {
            b.iter(|| vk.verify_dalek(&sig, &msg))
        });

        let prepared = vk.prepare();
        group.bench_with_input(
            BenchmarkId::new("5. verify_prepared (full)", n),
            &n,
            |b, _| b.iter(|| prepared.verify(&sig, &msg)),
        );

        // One full lane group; criterion reports per-signature throughput.
        let vk_bytes_typed = VerificationKeyBytes::from(vk_bytes);
        let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = (0..8)
            .map(|_| (vk_bytes_typed, sig, msg.as_slice()))
            .collect();
        group.throughput(Throughput::Elements(8));
        group.bench_with_input(BenchmarkId::new("6. lanes x8 (per-sig)", n), &n, |b, _| {
            b.iter(|| lanes::verify_batch(&items))
        });
    }

    {
        let (vk, _, _) = inputs(0);
        group.bench_function("VerificationKey::prepare", |b| b.iter(|| vk.prepare()));
    }
    group.finish();
}

/// Raw SHA-512 throughput, to see whether the hardware `sha512` path is live.
fn bench_sha512_raw(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512 raw");
    for &n in [64usize, 128, 1024, 8192].iter() {
        let data = vec![0x5Au8; n];
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::new("Sha512", n), &n, |b, _| {
            b.iter(|| Sha512::digest(&data))
        });
    }
    group.finish();
}

/// The individual curve/scalar steps inside `verify_zebra`.
fn bench_post_hash_steps(c: &mut Criterion) {
    let mut group = c.benchmark_group("post-hash steps");

    let (vk, sig, msg) = inputs(0);
    let vk_bytes: [u8; 32] = vk.into();
    let h = challenge_scalar(&vk_bytes, &sig, &msg);
    let (_rho, tau, _flip) = h.heea_decompose();
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sig.s_bytes())).unwrap();

    group.bench_function("Scalar::from_bytes_mod_order_wide", |b| {
        let wide = [0x33u8; 64];
        b.iter(|| Scalar::from_bytes_mod_order_wide(&wide))
    });

    group.bench_function("heea_decompose", |b| b.iter(|| h.heea_decompose()));

    group.bench_function("Scalar::from_canonical_bytes", |b| {
        b.iter(|| Option::<Scalar>::from(Scalar::from_canonical_bytes(*sig.s_bytes())))
    });

    group.bench_function("CompressedEdwardsY::decompress (R)", |b| {
        let R = CompressedEdwardsY(*sig.r_bytes());
        b.iter(|| R.decompress().unwrap())
    });

    group.bench_function("Scalar mul (tau * s)", |b| b.iter(|| tau * s));

    group.bench_function("mul_by_cofactor + is_identity", |b| {
        let P = EdwardsPoint::mul_base(&s);
        b.iter(|| P.mul_by_cofactor().is_identity())
    });

    group.bench_function("vartime_double_scalar_mul_basepoint + compress", |b| {
        let A = EdwardsPoint::mul_base(&h);
        b.iter(|| EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &A, &s).compress())
    });

    group.finish();
}

/// Lane-width sweep for the curve stage: same group of eight, different vector
/// width. `serial x8` is the single-signature path over the same eight inputs.
fn bench_lane_widths(c: &mut Criterion) {
    let mut group = c.benchmark_group("lane widths");
    group.throughput(Throughput::Elements(8));

    for &n in [0usize, 1232].iter() {
        let (vk, sig, msg) = inputs(n);
        let vk_bytes: [u8; 32] = vk.into();
        let vk_bytes_typed = VerificationKeyBytes::from(vk_bytes);
        let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = (0..8)
            .map(|_| (vk_bytes_typed, sig, msg.as_slice()))
            .collect();

        for (label, engine) in [
            ("portable", lanes::Engine::Portable),
            ("neon x2", lanes::Engine::Neon(2)),
            ("neon x4", lanes::Engine::Neon(4)),
            ("neon x8", lanes::Engine::Neon(8)),
        ] {
            group.bench_with_input(BenchmarkId::new(label, n), &n, |b, _| {
                b.iter(|| lanes::verify_batch_with(&items, engine))
            });
        }

        group.bench_with_input(BenchmarkId::new("serial x8", n), &n, |b, _| {
            b.iter(|| {
                let mut ok = true;
                for (k, s, m) in &items {
                    ok &= VerificationKey::try_from(*k)
                        .and_then(|v| v.verify(s, m))
                        .is_ok();
                }
                ok
            })
        });
    }
    group.finish();
}

/// A deterministic LCG, so every build benches the same eight messages.
fn lcg(state: &mut u32) -> usize {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    (*state >> 8) as usize
}

/// A ragged length spread, drawn deterministically from `lo..hi`.
fn ragged(seed: u32, n: usize, lo: usize, hi: usize) -> Vec<usize> {
    let mut state = seed;
    (0..n).map(|_| lo + lcg(&mut state) % (hi - lo)).collect()
}

/// Uniform and ragged batches: one group of eight, and 64 signatures, where a
/// ragged spread has more than one group to be distributed over.
fn bench_lane_group_shapes(c: &mut Criterion) {
    let mut group = c.benchmark_group("lane group shapes");

    let shapes: [(&str, Vec<usize>); 8] = [
        ("uniform 1232", vec![1232; 8]),
        ("uniform 4096", vec![4096; 8]),
        ("ragged 200..1232", ragged(0x0BAD_C0DE, 8, 200, 1232)),
        ("ragged 200..4096", ragged(0x1337_BEEF, 8, 200, 4096)),
        ("uniform 1232 x64", vec![1232; 64]),
        ("uniform 4096 x64", vec![4096; 64]),
        ("ragged 200..1232 x64", ragged(0x0BAD_C0DE, 64, 200, 1232)),
        ("ragged 200..4096 x64", ragged(0x1337_BEEF, 64, 200, 4096)),
    ];

    for (label, lens) in shapes {
        let sk = SigningKey::from([11u8; 32]);
        let vk_bytes = VerificationKeyBytes::from(&sk);
        let msgs: Vec<Vec<u8>> = lens.iter().map(|&n| vec![0xABu8; n]).collect();
        let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = msgs
            .iter()
            .map(|m| (vk_bytes, sk.sign(m), m.as_slice()))
            .collect();
        group.throughput(Throughput::Elements(items.len() as u64));
        group.bench_function(label, |b| b.iter(|| lanes::verify_batch(&items)));
    }
    group.finish();
}

/// One `W`-lane NEON field multiply against `W` serial radix-2^51 ones.
///
/// `serial` covers eight lanes, so divide a vector row by `8 / W` to compare.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
fn bench_field_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("field mul probe");
    for (label, engine) in [
        ("serial x8", lanes::Engine::Portable),
        ("neon x2", lanes::Engine::Neon(2)),
        ("neon x4", lanes::Engine::Neon(4)),
        ("neon x8", lanes::Engine::Neon(8)),
    ] {
        group.bench_function(label, |b| {
            b.iter(|| lanes::field_mul_probe(engine, 1000))
        });
    }
    group.finish();
}

#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
fn bench_field_mul(_c: &mut Criterion) {}

criterion_group!(
    breakdown,
    bench_hash_vs_verify,
    bench_sha512_raw,
    bench_post_hash_steps,
    bench_lane_widths,
    bench_lane_group_shapes,
    bench_field_mul
);
criterion_main!(breakdown);
