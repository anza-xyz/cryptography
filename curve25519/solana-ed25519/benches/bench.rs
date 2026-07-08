use core::convert::TryFrom;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
#[cfg(all(
    feature = "avx512",
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512dq",
    target_feature = "avx512ifma",
))]
use curve25519::ed_sigs::avx512;
use curve25519::ed_sigs::*;
use ed25519::signature::Verifier as _;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;

fn signing_key_from_index(index: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&index.to_le_bytes());
    SigningKey::from(seed)
}

fn sigs_with_distinct_pubkeys() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    (0u64..).map(|i| {
        let sk = signing_key_from_index(i);
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

#[cfg(all(feature = "alloc", feature = "rand_core"))]
fn sigs_with_same_pubkey() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    let sk = signing_key_from_index(0);
    let pk_bytes = VerificationKeyBytes::from(&sk);
    std::iter::repeat_with(move || {
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

fn single_verify_inputs() -> (VerificationKey, Signature, DalekVerifyingKey) {
    let sk = signing_key_from_index(0);
    let vk = VerificationKey::from(&sk);
    let sig = sk.sign(b"");
    let vk_bytes: [u8; 32] = vk.into();

    let dalek_vk = DalekVerifyingKey::from_bytes(&vk_bytes).expect("dalek verification key");

    (vk, sig, dalek_vk)
}

#[cfg(all(
    feature = "avx512",
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512dq",
    target_feature = "avx512ifma",
))]
fn avx512_inputs_with_distinct_pubkeys(n: usize) -> Vec<avx512::VerifyInput<'static>> {
    (0u64..n as u64)
        .map(|i| {
            let sk = signing_key_from_index(i);
            avx512::VerifyInput {
                public_key: VerificationKeyBytes::from(&sk).into(),
                signature: sk.sign(b"").into(),
                message: b"",
            }
        })
        .collect()
}

#[cfg(all(
    feature = "avx512",
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512dq",
    target_feature = "avx512ifma",
))]
fn avx512_inputs_with_same_pubkey(n: usize) -> Vec<avx512::VerifyInput<'static>> {
    let sk = signing_key_from_index(0);
    let public_key = VerificationKeyBytes::from(&sk).into();
    (0..n)
        .map(|_| avx512::VerifyInput {
            public_key,
            signature: sk.sign(b"").into(),
            message: b"",
        })
        .collect()
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        let sigs = sigs_with_distinct_pubkeys().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs: &Vec<(VerificationKeyBytes, Signature)>| {
                b.iter(|| {
                    for (vk_bytes, sig) in sigs.iter() {
                        let _ = VerificationKey::try_from(*vk_bytes)
                            .and_then(|vk: VerificationKey| vk.verify(sig, b""));
                    }
                })
            },
        );
        #[cfg(all(feature = "alloc", feature = "rand_core"))]
        group.bench_with_input(
            BenchmarkId::new("Signatures with Distinct Pubkeys", n),
            &sigs,
            |b, sigs: &Vec<(VerificationKeyBytes, Signature)>| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(rand::thread_rng())
                })
            },
        );
        #[cfg(all(feature = "alloc", feature = "rand_core"))]
        let sigs = sigs_with_same_pubkey().take(*n).collect::<Vec<_>>();
        #[cfg(all(feature = "alloc", feature = "rand_core"))]
        group.bench_with_input(
            BenchmarkId::new("Signatures with the Same Pubkey", n),
            &sigs,
            |b, sigs: &Vec<(VerificationKeyBytes, Signature)>| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(rand::thread_rng())
                })
            },
        );
        #[cfg(all(
            feature = "avx512",
            target_arch = "x86_64",
            target_feature = "avx512f",
            target_feature = "avx512dq",
            target_feature = "avx512ifma",
        ))]
        {
            let avx512_distinct_inputs = avx512_inputs_with_distinct_pubkeys(*n);
            group.bench_with_input(
                BenchmarkId::new("AVX512 Zip215 Distinct Pubkeys", n),
                &avx512_distinct_inputs,
                |b, inputs: &Vec<avx512::VerifyInput<'static>>| {
                    let mut verifier = avx512::Verifier::new();
                    let mut out = vec![false; inputs.len()];
                    b.iter(|| {
                        verifier.verify_batch(inputs, &mut out);
                        std::hint::black_box(&out);
                    })
                },
            );

            let avx512_same_inputs = avx512_inputs_with_same_pubkey(*n);
            group.bench_with_input(
                BenchmarkId::new("AVX512 Zip215 Same Pubkey Hot Cache", n),
                &avx512_same_inputs,
                |b, inputs: &Vec<avx512::VerifyInput<'static>>| {
                    let mut verifier = avx512::Verifier::with_cache(
                        avx512::VerifyPolicy::Zip215,
                        avx512::HotKeyCache::with_capacity(1),
                    );
                    let mut out = vec![false; inputs.len()];
                    verifier.verify_batch(inputs, &mut out);
                    b.iter(|| {
                        verifier.verify_batch(inputs, &mut out);
                        std::hint::black_box(&out);
                    })
                },
            );
        }
    }
    group.finish();
}

fn bench_single_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Verification");

    group.bench_function("local_verify_zebra", |b| {
        let (vk, sig, _) = single_verify_inputs();
        b.iter(|| {
            let _ = vk.verify_zebra(&sig, b"");
        })
    });

    group.bench_function("local_verify_dalek", |b| {
        let (vk, sig, _) = single_verify_inputs();
        b.iter(|| {
            let _ = vk.verify_dalek(&sig, b"");
        })
    });

    group.bench_function("crates_io_ed25519_dalek", |b| {
        let (_, sig, dalek_vk) = single_verify_inputs();
        b.iter(|| {
            let _ = dalek_vk.verify(b"", &sig);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_single_verify, bench_batch_verify,);
criterion_main!(benches);
