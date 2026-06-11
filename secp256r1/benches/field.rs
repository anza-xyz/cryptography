use criterion::{Criterion, black_box, criterion_group, criterion_main};
use p256::{FieldElement as P256FieldElement, elliptic_curve::ff::PrimeField};
use secp256r1::field::FieldElement;

const A: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
];
const B: [u8; 32] = [
    0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
];

#[link(name = "crypto")]
unsafe extern "C" {
    fn ecp_nistz256_to_mont(res: *mut u64, input: *const u64);
    fn ecp_nistz256_add(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_sub(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_mul_mont(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_sqr_mont(res: *mut u64, a: *const u64);
}

#[derive(Clone, Copy)]
struct Fixture {
    rust_a: FieldElement,
    rust_b: FieldElement,
    openssl_a: [u64; 4],
    openssl_b: [u64; 4],
    p256_a: P256FieldElement,
    p256_b: P256FieldElement,
}

impl Fixture {
    fn new() -> Self {
        let raw_a = limbs_from_be_bytes(A);
        let raw_b = limbs_from_be_bytes(B);
        let mut openssl_a = [0u64; 4];
        let mut openssl_b = [0u64; 4];

        unsafe {
            ecp_nistz256_to_mont(openssl_a.as_mut_ptr(), raw_a.as_ptr());
            ecp_nistz256_to_mont(openssl_b.as_mut_ptr(), raw_b.as_ptr());
        }

        Self {
            rust_a: FieldElement::from_be_bytes(A).unwrap(),
            rust_b: FieldElement::from_be_bytes(B).unwrap(),
            openssl_a,
            openssl_b,
            p256_a: p256_field(A),
            p256_b: p256_field(B),
        }
    }
}

fn p256_field(bytes: [u8; 32]) -> P256FieldElement {
    Option::from(P256FieldElement::from_repr(bytes.into())).unwrap()
}

fn limbs_from_be_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];

    for (i, chunk) in bytes.chunks_exact(8).rev().enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    limbs
}

fn bench_field_add(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_field_add");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) + black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) + black_box(fixture.p256_b));
    });

    group.bench_function("openssl_ecp_nistz256", |b| {
        b.iter(|| {
            let mut out = [0u64; 4];
            unsafe {
                ecp_nistz256_add(
                    out.as_mut_ptr(),
                    black_box(fixture.openssl_a).as_ptr(),
                    black_box(fixture.openssl_b).as_ptr(),
                );
            }
            black_box(out)
        });
    });

    group.finish();
}

fn bench_field_sub(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_field_sub");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) - black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) - black_box(fixture.p256_b));
    });

    group.bench_function("openssl_ecp_nistz256", |b| {
        b.iter(|| {
            let mut out = [0u64; 4];
            unsafe {
                ecp_nistz256_sub(
                    out.as_mut_ptr(),
                    black_box(fixture.openssl_a).as_ptr(),
                    black_box(fixture.openssl_b).as_ptr(),
                );
            }
            black_box(out)
        });
    });

    group.finish();
}

fn bench_field_mul(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_field_mul");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a) * black_box(fixture.rust_b));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a) * black_box(fixture.p256_b));
    });

    group.bench_function("openssl_ecp_nistz256", |b| {
        b.iter(|| {
            let mut out = [0u64; 4];
            unsafe {
                ecp_nistz256_mul_mont(
                    out.as_mut_ptr(),
                    black_box(fixture.openssl_a).as_ptr(),
                    black_box(fixture.openssl_b).as_ptr(),
                );
            }
            black_box(out)
        });
    });

    group.finish();
}

fn bench_field_square(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_field_square");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_a).square());
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_a).square());
    });

    group.bench_function("openssl_ecp_nistz256", |b| {
        b.iter(|| {
            let mut out = [0u64; 4];
            unsafe {
                ecp_nistz256_sqr_mont(out.as_mut_ptr(), black_box(fixture.openssl_a).as_ptr());
            }
            black_box(out)
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
