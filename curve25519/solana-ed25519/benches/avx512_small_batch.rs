//! Compare the existing ZIP-215 MSM batch verifier with the AVX-512 facade.
//!
//! Run on an AVX-512-capable x86_64 host with:
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p solana-ed25519 \
//!     --features avx512,rand_core --bench avx512_small_batch
//! ```

#[cfg(ed25519_avx512)]
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
#[cfg(ed25519_avx512)]
use solana_ed25519::ed_sigs::{
    Signature, SigningKey, VerificationKeyBytes,
    avx512::{VerifyInput, Zip215Verifier},
    batch,
};
#[cfg(ed25519_avx512)]
use std::hint::black_box;

#[cfg(ed25519_avx512)]
const MESSAGE: &[u8] = b"";

#[cfg(ed25519_avx512)]
fn signing_key_from_index(index: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&index.to_le_bytes());
    SigningKey::from(seed)
}

#[cfg(ed25519_avx512)]
fn inputs(count: usize) -> Vec<(VerificationKeyBytes, Signature)> {
    (0..count as u64)
        .map(|index| {
            let signing_key = signing_key_from_index(index);
            (
                VerificationKeyBytes::from(&signing_key),
                signing_key.sign(MESSAGE),
            )
        })
        .collect()
}

#[cfg(ed25519_avx512)]
fn bench_small_batches(c: &mut Criterion) {
    let mut group = c.benchmark_group("AVX-512 small batch");

    for count in 1usize..=8 {
        let msm_inputs = inputs(count);
        let simd_inputs = msm_inputs
            .iter()
            .map(|(public_key, signature)| VerifyInput {
                public_key: (*public_key).into(),
                signature: (*signature).into(),
                message: MESSAGE,
            })
            .collect::<Vec<_>>();
        let mut simd_output = vec![false; count];
        let mut simd_verifier = Zip215Verifier::new();

        simd_verifier.verify_batch(&simd_inputs, &mut simd_output);
        assert!(simd_output.iter().all(|valid| *valid));

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("MSM batch (ZIP-215)", count),
            &msm_inputs,
            |b, msm_inputs| {
                b.iter(|| {
                    let mut verifier = batch::Verifier::new();
                    for (public_key, signature) in msm_inputs.iter().cloned() {
                        verifier.queue((public_key, signature, MESSAGE));
                    }
                    black_box(verifier.verify())
                });
            },
        );
        group.bench_function(BenchmarkId::new("AVX-512 facade", count), |b| {
            b.iter(|| {
                simd_verifier.verify_batch(black_box(&simd_inputs), &mut simd_output);
                black_box(&simd_output);
            });
        });
    }

    group.finish();
}

#[cfg(ed25519_avx512)]
criterion_group!(benches, bench_small_batches);
#[cfg(ed25519_avx512)]
criterion_main!(benches);

// Keep all-target checks valid when the CPU target features are absent.
#[cfg(not(ed25519_avx512))]
fn main() {}
