use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use openssl::bn::{BigNum, BigNumContext};
use p256::{FieldElement as P256FieldElement, elliptic_curve::ff::PrimeField};
use solana_secp256r1::field::FieldElement;

const A: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
];
const B: [u8; 32] = [
    0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
];
const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

struct Fixture {
    rust_a: FieldElement,
    rust_b: FieldElement,
    openssl_a: BigNum,
    openssl_b: BigNum,
    openssl_p: BigNum,
    p256_a: P256FieldElement,
    p256_b: P256FieldElement,
}

impl Fixture {
    fn new() -> Self {
        Self {
            rust_a: FieldElement::from_be_bytes(A).unwrap(),
            rust_b: FieldElement::from_be_bytes(B).unwrap(),
            openssl_a: BigNum::from_slice(&A).unwrap(),
            openssl_b: BigNum::from_slice(&B).unwrap(),
            openssl_p: BigNum::from_slice(&P).unwrap(),
            p256_a: p256_field(A),
            p256_b: p256_field(B),
        }
    }
}

fn p256_field(bytes: [u8; 32]) -> P256FieldElement {
    Option::from(P256FieldElement::from_repr(bytes.into())).unwrap()
}

fn bench_field_add(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut context = BigNumContext::new().unwrap();
    let mut openssl_out = BigNum::new().unwrap();
    let mut group = c.benchmark_group("solana_secp256r1_field_add");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) + black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) + black_box(fixture.p256_b));
    });

    group.bench_function("openssl_bn_mod_add", |b| {
        b.iter(|| {
            openssl_out
                .mod_add(
                    black_box(&fixture.openssl_a),
                    black_box(&fixture.openssl_b),
                    black_box(&fixture.openssl_p),
                    &mut context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_field_sub(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut context = BigNumContext::new().unwrap();
    let mut openssl_out = BigNum::new().unwrap();
    let mut group = c.benchmark_group("solana_secp256r1_field_sub");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) - black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) - black_box(fixture.p256_b));
    });

    group.bench_function("openssl_bn_mod_sub", |b| {
        b.iter(|| {
            openssl_out
                .mod_sub(
                    black_box(&fixture.openssl_a),
                    black_box(&fixture.openssl_b),
                    black_box(&fixture.openssl_p),
                    &mut context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_field_mul(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut context = BigNumContext::new().unwrap();
    let mut openssl_out = BigNum::new().unwrap();
    let mut group = c.benchmark_group("solana_secp256r1_field_mul");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) * black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) * black_box(fixture.p256_b));
    });

    group.bench_function("openssl_bn_mod_mul", |b| {
        b.iter(|| {
            openssl_out
                .mod_mul(
                    black_box(&fixture.openssl_a),
                    black_box(&fixture.openssl_b),
                    black_box(&fixture.openssl_p),
                    &mut context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_field_square(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut context = BigNumContext::new().unwrap();
    let mut openssl_out = BigNum::new().unwrap();
    let mut group = c.benchmark_group("solana_secp256r1_field_square");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a).square());
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a).square());
    });

    group.bench_function("openssl_bn_mod_sqr", |b| {
        b.iter(|| {
            openssl_out
                .mod_sqr(
                    black_box(&fixture.openssl_a),
                    black_box(&fixture.openssl_p),
                    &mut context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_add,
    bench_field_sub,
    bench_field_mul,
    bench_field_square
);
criterion_main!(benches);
