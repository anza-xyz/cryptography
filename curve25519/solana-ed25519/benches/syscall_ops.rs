//! Compare compressed-point syscall helpers with decompression and upstream dalek.
//! Inputs and agreement cases are shared with `tests/syscall_ops.rs`.

#[path = "../tests/support/syscall_ops.rs"]
mod support;

use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use std::{hint::black_box, time::Duration};
use support::{Corpus, Encoding, check_group_op, check_validation, ours, upstream};

fn bench_inputs<T, R>(
    g: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    inputs: &[T],
    f: impl Fn(&T) -> R,
) {
    assert!(!inputs.is_empty());
    g.bench_function(name, |b| {
        let mut index = 0;
        b.iter(|| {
            let result = f(black_box(&inputs[index]));
            index += 1;
            if index == inputs.len() {
                index = 0;
            }
            result
        });
    });
}

fn bench_validation(
    c: &mut Criterion,
    curve: &str,
    corpus: &Corpus,
    operation: &str,
    validate: impl Fn(&Encoding) -> bool,
    reference: Option<fn(&Encoding) -> bool>,
) {
    if let Some(reference) = reference {
        check_validation(corpus, &validate, reference);
    }
    for (case, inputs) in &corpus.validation {
        let mut group = c.benchmark_group(format!("{curve}/corpus/{case}"));
        bench_inputs(&mut group, operation, inputs, &validate);
    }
}

type GroupOp = fn(&Encoding, &Encoding) -> Option<Encoding>;

fn bench_group_op(
    c: &mut Criterion,
    curve: &str,
    corpus: &Corpus,
    operation: &str,
    apply: impl Fn(&Encoding, &Encoding) -> Option<Encoding>,
    reference: Option<GroupOp>,
) {
    if let Some(reference) = reference {
        check_group_op(corpus, &apply, reference);
    }
    for (case, inputs) in &corpus.pairs {
        let mut group = c.benchmark_group(format!("{curve}/corpus/{case}"));
        bench_inputs(&mut group, operation, inputs, |(a, b)| apply(a, b));
    }
}

fn bench_corpus(c: &mut Criterion) {
    let edwards = Corpus::edwards();
    bench_validation(
        c,
        "edwards",
        &edwards,
        "validate",
        ours::edwards_validate,
        Some(upstream::edwards_validate),
    );
    bench_validation(
        c,
        "edwards",
        &edwards,
        "validate_upstream",
        upstream::edwards_validate,
        None,
    );
    bench_validation(
        c,
        "edwards",
        &edwards,
        "validate_decompress",
        ours::edwards_validate_decompress,
        Some(upstream::edwards_validate),
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "add",
        ours::edwards_add,
        Some(upstream::edwards_add),
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "add_decompress",
        ours::edwards_add_decompress,
        Some(upstream::edwards_add),
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "add_upstream",
        upstream::edwards_add,
        None,
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "sub",
        ours::edwards_sub,
        Some(upstream::edwards_sub),
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "sub_decompress",
        ours::edwards_sub_decompress,
        Some(upstream::edwards_sub),
    );
    bench_group_op(
        c,
        "edwards",
        &edwards,
        "sub_upstream",
        upstream::edwards_sub,
        None,
    );
    let ristretto = Corpus::ristretto();
    bench_validation(
        c,
        "ristretto",
        &ristretto,
        "validate",
        ours::ristretto_validate,
        Some(upstream::ristretto_validate),
    );
    bench_validation(
        c,
        "ristretto",
        &ristretto,
        "validate_upstream",
        upstream::ristretto_validate,
        None,
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "add",
        ours::ristretto_add,
        Some(upstream::ristretto_add),
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "add_decompress",
        ours::ristretto_add_decompress,
        Some(upstream::ristretto_add),
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "add_upstream",
        upstream::ristretto_add,
        None,
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "sub",
        ours::ristretto_sub,
        Some(upstream::ristretto_sub),
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "sub_decompress",
        ours::ristretto_sub_decompress,
        Some(upstream::ristretto_sub),
    );
    bench_group_op(
        c,
        "ristretto",
        &ristretto,
        "sub_upstream",
        upstream::ristretto_sub,
        None,
    );
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_corpus
}
criterion_main!(benches);
