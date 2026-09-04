//! What reusing an already-decompressed verification key buys in a batch.
//!
//! Compares `queue`, which decompresses `A` per distinct key at verify time,
//! against `queue_prepared`, which reuses the point inside a `VerificationKey`.
#![cfg(all(feature = "alloc", feature = "rand_core"))]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use solana_ed25519::ed_sigs::*;

const MSG: &[u8] = b"BatchVerifyTest";

fn keys(n: usize, distinct: bool) -> Vec<(VerificationKey, VerificationKeyBytes, Signature)> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(if distinct { i as u64 } else { 0 }).to_le_bytes());
            let sk = SigningKey::from(seed);
            (
                VerificationKey::from(&sk),
                VerificationKeyBytes::from(&sk),
                sk.sign(MSG),
            )
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    for (label, distinct) in [("distinct pubkeys", true), ("same pubkey", false)] {
        let mut g = c.benchmark_group(label);
        for n in [8usize, 32, 64] {
            let ks = keys(n, distinct);
            g.throughput(Throughput::Elements(n as u64));

            g.bench_with_input(BenchmarkId::new("queue (decompress A)", n), &n, |b, _| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (_, vkb, sig) in ks.iter() {
                        batch.queue((*vkb, *sig, MSG));
                    }
                    batch.verify()
                })
            });

            g.bench_with_input(BenchmarkId::new("queue_prepared (cached A)", n), &n, |b, _| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk, _, sig) in ks.iter() {
                        batch.queue_prepared(vk, *sig, MSG);
                    }
                    batch.verify()
                })
            });
        }
        g.finish();
    }
}

criterion_group!(x, bench);
criterion_main!(x);
