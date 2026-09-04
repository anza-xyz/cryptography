//! Where a lane group's time goes: hashing, scalar preparation, decompression
//! with table build, and the curve stage.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use solana_ed25519::ed_sigs::lanes::{
    challenge_hashes_only, curve_stage_only, decompress_table_only, prepare_group_only,
    verify_batch,
};
use solana_ed25519::ed_sigs::{Signature, SigningKey, VerificationKeyBytes};

/// Eight distinct signers and messages, so nothing repeats across lanes.
fn group(msg_len: usize) -> (Vec<VerificationKeyBytes>, Vec<Signature>, Vec<Vec<u8>>) {
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    let mut msgs = Vec::new();
    for i in 0..8u8 {
        let sk = SigningKey::from([i.wrapping_mul(37).wrapping_add(11); 32]);
        let msg: Vec<u8> = (0..msg_len)
            .map(|j| (j as u8).wrapping_mul(i + 3))
            .collect();
        sigs.push(sk.sign(&msg));
        keys.push(VerificationKeyBytes::from(&sk));
        msgs.push(msg);
    }
    (keys, sigs, msgs)
}

fn bench_breakdown(c: &mut Criterion) {
    let mut group_bench = c.benchmark_group("lane breakdown");
    group_bench.throughput(Throughput::Elements(8));

    for &n in [0usize, 1232, 4096].iter() {
        let (keys, sigs, msgs) = group(n);
        let items: [(VerificationKeyBytes, Signature, &[u8]); 8] =
            core::array::from_fn(|l| (keys[l], sigs[l], msgs[l].as_slice()));
        let a: [[u8; 32]; 8] = core::array::from_fn(|l| <[u8; 32]>::from(keys[l]));
        let r: [[u8; 32]; 8] = core::array::from_fn(|l| *sigs[l].r_bytes());
        let prepared = prepare_group_only(&items);

        group_bench.bench_with_input(BenchmarkId::new("1. full group", n), &n, |b, _| {
            b.iter(|| verify_batch(&items))
        });
        group_bench.bench_with_input(BenchmarkId::new("2. hashes", n), &n, |b, _| {
            b.iter(|| challenge_hashes_only(&items))
        });
        group_bench.bench_with_input(
            BenchmarkId::new("3. prepare (hash + scalar)", n),
            &n,
            |b, _| b.iter(|| prepare_group_only(&items)),
        );
        group_bench.bench_with_input(BenchmarkId::new("4. curve stage", n), &n, |b, _| {
            b.iter(|| curve_stage_only(&prepared))
        });
        if n == 0 {
            group_bench.bench_function("5. decompress + table, A", |b| {
                b.iter(|| decompress_table_only(&a))
            });
            group_bench.bench_function("5. decompress + table, R", |b| {
                b.iter(|| decompress_table_only(&r))
            });
        }
    }
    group_bench.finish();
}

criterion_group!(breakdown, bench_breakdown);
criterion_main!(breakdown);
