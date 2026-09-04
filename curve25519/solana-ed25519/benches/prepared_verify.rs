//! What caching a verification key buys on the single-verify path.
//!
//! Three tiers, in increasing amounts of precomputation reused per call:
//! `try_from` plus verify decompresses `A` every time, `VerificationKey::verify`
//! has `A` already but builds a table per call, and
//! `PreparedVerificationKey::verify` caches both.
#![cfg(all(feature = "alloc", feature = "digest"))]

use criterion::{Criterion, criterion_group, criterion_main};
use solana_ed25519::ed_sigs::*;

fn bench(c: &mut Criterion) {
    let sk = SigningKey::from([7u8; 32]);
    let vk = VerificationKey::from(&sk);
    let vk_bytes: [u8; 32] = vk.into();
    let prepared = vk.prepare();
    let msg = b"";
    let sig = sk.sign(msg);

    // All three tiers must agree before any of them is timed.
    assert!(vk.verify(&sig, msg).is_ok());
    assert!(prepared.verify(&sig, msg).is_ok());
    let bad = sk.sign(b"other");
    assert!(vk.verify(&bad, msg).is_err());
    assert!(prepared.verify(&bad, msg).is_err());

    let mut g = c.benchmark_group("single verify tiers");

    g.bench_function("1. try_from + verify (agave today)", |b| {
        b.iter(|| {
            VerificationKey::try_from(vk_bytes)
                .and_then(|k| k.verify(&sig, msg))
        })
    });

    g.bench_function("2. VerificationKey::verify", |b| {
        b.iter(|| vk.verify(&sig, msg))
    });

    g.bench_function("3. PreparedVerificationKey::verify", |b| {
        b.iter(|| prepared.verify(&sig, msg))
    });

    g.finish();
}

criterion_group!(x, bench);
criterion_main!(x);
