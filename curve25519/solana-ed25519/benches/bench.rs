use core::convert::TryFrom;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ed25519::signature::Verifier as _;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
use solana_ed25519::ed_sigs::*;

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
                    batch.verify()
                })
            },
        );
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Wide lanes (per-sig verdicts)", n),
            &sigs,
            |b, sigs: &Vec<(VerificationKeyBytes, Signature)>| {
                let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = sigs
                    .iter()
                    .map(|(vk_bytes, sig)| (*vk_bytes, *sig, &b""[..]))
                    .collect();
                b.iter(|| lanes::verify_batch(&items))
            },
        );
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Wide lanes prepared (hot keys)", n),
            &sigs,
            |b, sigs: &Vec<(VerificationKeyBytes, Signature)>| {
                let keys: Vec<lanes::PreparedLaneKey> = sigs
                    .iter()
                    .map(|(vk_bytes, _)| lanes::PreparedLaneKey::new(*vk_bytes).unwrap())
                    .collect();
                let items: Vec<(&lanes::PreparedLaneKey, Signature, &[u8])> = sigs
                    .iter()
                    .enumerate()
                    .map(|(i, (_, sig))| (&keys[i], *sig, &b""[..]))
                    .collect();
                b.iter(|| lanes::verify_batch_prepared(&items))
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
                    batch.verify()
                })
            },
        );
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
