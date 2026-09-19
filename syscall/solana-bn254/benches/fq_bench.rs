//! Primitive baselines for the portable Fq backend, including all per-call work.
//! Chains measure dependent work; independent batches measure throughput.

use ark_bn254::Fq as ArkFq;
use ark_ff::{AdditiveGroup as _, Field as _, PrimeField};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Fq, MontgomeryBackend, U256};
use std::hint::black_box;

type B = Backend<Fq>;

#[inline(always)]
fn chain<T>(mut value: T, length: usize, mut step: impl FnMut(T) -> T) -> T {
    for _ in 0..length {
        value = step(value);
    }
    value
}

fn measure_pair<O, A>(
    c: &mut Criterion,
    name: &str,
    count: u64,
    mut ours: impl FnMut() -> O,
    mut arkworks: impl FnMut() -> A,
) {
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Elements(count));
    group.bench_function("solana-bn254", |b| b.iter(|| black_box(ours())));
    group.bench_function("arkworks", |b| b.iter(|| black_box(arkworks())));
    group.finish();
}

fn bench_fq(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x6671_5f62_656e_6368);
    let radix = ArkFq::from(2u64).pow([256u64]);
    let raw = |value: ArkFq| U256::new((value * radix).into_bigint().0);
    let inputs: [(ArkFq, U256); 32] = std::array::from_fn(|_| {
        let value = loop {
            let candidate = ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
            if candidate != ArkFq::ZERO {
                break candidate;
            }
        };
        (value, raw(value))
    });
    let (ark_start, start) = inputs[0];
    let (ark_factor, factor) = inputs[1];
    let ark_batch = std::array::from_fn::<_, 8, _>(|i| inputs[i].0);
    let batch = std::array::from_fn::<_, 8, _>(|i| inputs[i].1);

    // Check every fixture and each chain using independently constructed
    // Montgomery residues, before timing either implementation.
    for (value, mont) in inputs {
        assert_eq!(B::to_mont(&U256::new(value.into_bigint().0)), mont);
        assert_eq!(B::inv(&mont), Some(raw(value.inverse().unwrap())));
        assert_eq!(B::mul(&mont, &factor), raw(value * ark_factor));
        assert_eq!(B::sqr(&mont), raw(value.square()));
    }
    assert_eq!(
        chain(start, 64, |v| B::mul(&v, &factor)),
        raw(chain(ark_start, 64, |v| v * ark_factor))
    );
    assert_eq!(
        chain(start, 64, |v| B::sqr(&v)),
        raw(chain(ark_start, 64, |v| v.square()))
    );
    assert_eq!(
        chain(start, 16, |v| B::inv(&B::add(&v, &factor)).unwrap()),
        raw(chain(ark_start, 16, |v| (v + ark_factor)
            .inverse()
            .unwrap()))
    );

    measure_pair(
        c,
        "fq_mul_chain_64",
        64,
        || {
            let f = black_box(factor);
            chain(black_box(start), 64, |v| B::mul(&v, &f))
        },
        || {
            let f = black_box(ark_factor);
            chain(black_box(ark_start), 64, |v| v * f)
        },
    );
    measure_pair(
        c,
        "fq_sqr_chain_64",
        64,
        || chain(black_box(start), 64, |v| B::sqr(&v)),
        || chain(black_box(ark_start), 64, |v| v.square()),
    );
    // Includes one modular addition per inversion to avoid repeatedly
    // alternating between just two inputs. It is not pure inversion timing.
    measure_pair(
        c,
        "fq_inv_add_chain_16",
        16,
        || {
            let f = black_box(factor);
            chain(black_box(start), 16, |v| B::inv(&B::add(&v, &f)).unwrap())
        },
        || {
            let f = black_box(ark_factor);
            chain(black_box(ark_start), 16, |v| (v + f).inverse().unwrap())
        },
    );
    measure_pair(
        c,
        "fq_mul_independent_8",
        8,
        || {
            let f = black_box(factor);
            black_box(batch).map(|v| B::mul(&v, &f))
        },
        || {
            let f = black_box(ark_factor);
            black_box(ark_batch).map(|v| v * f)
        },
    );
    measure_pair(
        c,
        "fq_sqr_independent_8",
        8,
        || black_box(batch).map(|v| B::sqr(&v)),
        || black_box(ark_batch).map(|v| v.square()),
    );
    let mut ours_index = 0;
    let mut ark_index = 0;
    measure_pair(
        c,
        "fq_inv_varied",
        1,
        || {
            let value = black_box(inputs[ours_index].1);
            ours_index = (ours_index + 1) % inputs.len();
            B::inv(&value).unwrap()
        },
        || {
            let value = black_box(inputs[ark_index].0);
            ark_index = (ark_index + 1) % inputs.len();
            value.inverse().unwrap()
        },
    );
}

criterion_group!(benches, bench_fq);
criterion_main!(benches);
