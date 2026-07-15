use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use openssl::bn::{BigNum, BigNumContext};
use p256::{Scalar as P256Scalar, elliptic_curve::ff::PrimeField};
use solana_secp256r1::scalar::Scalar;

const A: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

const B: [u8; 32] = [
    0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
];

const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

struct Fixture {
    rust_a: Scalar,
    rust_b: Scalar,
    p256_a: P256Scalar,
    p256_b: P256Scalar,
    openssl_a: BigNum,
    openssl_order: BigNum,
}

impl Fixture {
    fn new() -> Self {
        Self {
            rust_a: Scalar::from_be_bytes(A).unwrap(),
            rust_b: Scalar::from_be_bytes(B).unwrap(),
            p256_a: p256_scalar(A),
            p256_b: p256_scalar(B),
            openssl_a: BigNum::from_slice(&A).unwrap(),
            openssl_order: BigNum::from_slice(&ORDER).unwrap(),
        }
    }
}

fn p256_scalar(bytes: [u8; 32]) -> P256Scalar {
    Option::from(P256Scalar::from_repr(bytes.into())).unwrap()
}

fn bench_scalar_mul(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("solana_secp256r1_scalar_mul");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) * black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) * black_box(fixture.p256_b));
    });

    group.finish();
}

fn bench_scalar_square(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("solana_secp256r1_scalar_square");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a).square());
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a).square());
    });

    group.finish();
}

fn bench_scalar_invert(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut context = BigNumContext::new().unwrap();
    let mut openssl_out = BigNum::new().unwrap();
    let mut group = c.benchmark_group("solana_secp256r1_scalar_invert");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a).invert().unwrap());
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a).invert().unwrap());
    });

    group.bench_function("openssl_bn_mod_inverse", |b| {
        b.iter(|| {
            openssl_out
                .mod_inverse(
                    black_box(&fixture.openssl_a),
                    black_box(&fixture.openssl_order),
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
    bench_scalar_mul,
    bench_scalar_square,
    bench_scalar_invert
);
criterion_main!(benches);
