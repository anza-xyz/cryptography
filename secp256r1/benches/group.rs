use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint},
    nid::Nid,
};
use p256::{
    AffinePoint as P256AffinePoint, ProjectivePoint as P256ProjectivePoint, Scalar,
    elliptic_curve::{ff::PrimeField, group::Group},
};
use secp256r1::group::{AffinePoint, ProjectivePoint};

const SCALAR: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

const MSM_8_POINTS: usize = 8;
const MSM_32_POINTS: usize = 32;

#[derive(Clone, Copy)]
struct Fixture {
    rust_g: ProjectivePoint,
    rust_2g: ProjectivePoint,
    rust_affine_g: AffinePoint,
    p256_g: P256ProjectivePoint,
    p256_2g: P256ProjectivePoint,
    p256_affine_g: P256AffinePoint,
    p256_scalar: Scalar,
}

impl Fixture {
    fn new() -> Self {
        let rust_g = ProjectivePoint::generator();
        let p256_g = P256ProjectivePoint::generator();

        Self {
            rust_g,
            rust_2g: rust_g.double(),
            rust_affine_g: AffinePoint::generator(),
            p256_g,
            p256_2g: p256_g.double(),
            p256_affine_g: P256AffinePoint::GENERATOR,
            p256_scalar: Option::<Scalar>::from(Scalar::from_repr(SCALAR.into())).unwrap(),
        }
    }
}

fn scalar_for_index(index: usize) -> [u8; 32] {
    let mut scalar = SCALAR;
    scalar[30] ^= (index as u8).wrapping_mul(17);
    scalar[31] = scalar[31].wrapping_add(index as u8);
    scalar
}

fn rust_msm_fixture(count: usize) -> (Vec<AffinePoint>, Vec<[u8; 32]>) {
    let generator = ProjectivePoint::generator();
    let mut point = generator;
    let mut points = Vec::with_capacity(count);
    let mut scalars = Vec::with_capacity(count);

    for i in 0..count {
        points.push(point.to_affine());
        scalars.push(scalar_for_index(i));
        point = point + generator;
    }

    (points, scalars)
}

fn p256_msm_fixture(count: usize) -> (Vec<P256ProjectivePoint>, Vec<Scalar>) {
    let generator = P256ProjectivePoint::generator();
    let mut point = generator;
    let mut points = Vec::with_capacity(count);
    let mut scalars = Vec::with_capacity(count);

    for i in 0..count {
        points.push(point);
        scalars
            .push(Option::<Scalar>::from(Scalar::from_repr(scalar_for_index(i).into())).unwrap());
        point = point + generator;
    }

    (points, scalars)
}

fn openssl_fixture() -> (EcGroup, BigNumContext, EcPoint, EcPoint) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let generator = group.generator_opt().unwrap().to_owned(&group).unwrap();
    let mut double_generator = EcPoint::new(&group).unwrap();
    double_generator
        .add(&group, &generator, &generator, &mut context)
        .unwrap();

    (group, context, generator, double_generator)
}

fn bench_group_double(c: &mut Criterion) {
    let fixture = Fixture::new();
    let (openssl_group, mut openssl_context, openssl_g, _) = openssl_fixture();
    let mut openssl_out = EcPoint::new(&openssl_group).unwrap();
    let mut group = c.benchmark_group("secp256r1_group_double");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_g).double());
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_g).double());
    });

    group.bench_function("openssl_ec_point_add_self", |b| {
        b.iter(|| {
            openssl_out
                .add(
                    &openssl_group,
                    black_box(&openssl_g),
                    black_box(&openssl_g),
                    &mut openssl_context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_group_add(c: &mut Criterion) {
    let fixture = Fixture::new();
    let (openssl_group, mut openssl_context, openssl_g, openssl_2g) = openssl_fixture();
    let mut openssl_out = EcPoint::new(&openssl_group).unwrap();
    let mut group = c.benchmark_group("secp256r1_group_add");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_2g) + black_box(fixture.rust_g));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_2g) + black_box(fixture.p256_g));
    });

    group.bench_function("openssl_ec_point_add", |b| {
        b.iter(|| {
            openssl_out
                .add(
                    &openssl_group,
                    black_box(&openssl_2g),
                    black_box(&openssl_g),
                    &mut openssl_context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_group_mixed_add(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_group_mixed_add");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_2g).add_mixed(black_box(fixture.rust_affine_g)));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_2g) + black_box(fixture.p256_affine_g));
    });

    group.finish();
}

fn bench_group_base_scalar_mul(c: &mut Criterion) {
    let fixture = Fixture::new();
    let (openssl_group, mut openssl_context, _, _) = openssl_fixture();
    let openssl_scalar = BigNum::from_slice(&SCALAR).unwrap();
    let mut openssl_out = EcPoint::new(&openssl_group).unwrap();
    let mut group = c.benchmark_group("secp256r1_group_base_scalar_mul");

    group.bench_function("rust_variable_base", |b| {
        b.iter(|| black_box(fixture.rust_g).mul_scalar_vartime(black_box(SCALAR)));
    });

    group.bench_function("rust_fixed_base", |b| {
        b.iter(|| ProjectivePoint::fixed_base_scalar_mul_vartime(black_box(SCALAR)));
    });

    group.bench_function("p256", |b| {
        b.iter(|| black_box(fixture.p256_g) * black_box(fixture.p256_scalar));
    });

    group.bench_function("openssl_ec_point_mul_generator", |b| {
        b.iter(|| {
            openssl_out
                .mul_generator2(
                    &openssl_group,
                    black_box(&openssl_scalar),
                    &mut openssl_context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_group_double_scalar_mul(c: &mut Criterion) {
    let fixture = Fixture::new();
    let rust_q = fixture.rust_2g.to_affine();
    let rust_msm_points = [AffinePoint::generator(), rust_q];
    let rust_msm_scalars = [SCALAR, SCALAR];
    let (openssl_group, mut openssl_context, _, openssl_q) = openssl_fixture();
    let openssl_scalar = BigNum::from_slice(&SCALAR).unwrap();
    let mut openssl_out = EcPoint::new(&openssl_group).unwrap();
    let mut group = c.benchmark_group("secp256r1_group_double_scalar_mul");

    group.bench_function("rust_separate_projective_q", |b| {
        b.iter(|| {
            ProjectivePoint::fixed_base_scalar_mul_vartime(black_box(SCALAR))
                + ProjectivePoint::from_affine(black_box(rust_q))
                    .mul_scalar_vartime(black_box(SCALAR))
        });
    });

    group.bench_function("rust_msm_window4", |b| {
        b.iter(|| {
            ProjectivePoint::multi_scalar_mul_vartime(
                black_box(&rust_msm_points),
                black_box(&rust_msm_scalars),
            )
            .unwrap()
        });
    });

    group.bench_function("rust_double_scalar", |b| {
        b.iter(|| {
            ProjectivePoint::double_scalar_mul_vartime(
                black_box(SCALAR),
                black_box(rust_q),
                black_box(SCALAR),
            )
        });
    });

    group.bench_function("p256", |b| {
        b.iter(|| {
            (black_box(fixture.p256_g) * black_box(fixture.p256_scalar))
                + (black_box(fixture.p256_2g) * black_box(fixture.p256_scalar))
        });
    });

    group.bench_function("openssl_ec_point_mul_full", |b| {
        b.iter(|| {
            openssl_out
                .mul_full(
                    &openssl_group,
                    black_box(&openssl_scalar),
                    black_box(&openssl_q),
                    black_box(&openssl_scalar),
                    &mut openssl_context,
                )
                .unwrap();
            black_box(&openssl_out);
        });
    });

    group.finish();
}

fn bench_group_multi_scalar_mul(c: &mut Criterion) {
    for count in [MSM_8_POINTS, MSM_32_POINTS] {
        let (rust_points, rust_scalars) = rust_msm_fixture(count);
        let (p256_points, p256_scalars) = p256_msm_fixture(count);
        let mut group = c.benchmark_group(format!("secp256r1_group_multi_scalar_mul_{count}"));

        group.bench_function("rust_msm_window4", |b| {
            b.iter(|| {
                ProjectivePoint::multi_scalar_mul_vartime(
                    black_box(rust_points.as_slice()),
                    black_box(rust_scalars.as_slice()),
                )
                .unwrap()
            });
        });

        group.bench_function("rust_separate", |b| {
            b.iter(|| {
                let mut out = ProjectivePoint::identity();

                for (point, scalar) in rust_points.iter().zip(rust_scalars.iter()) {
                    out = out
                        + ProjectivePoint::from_affine(black_box(*point))
                            .mul_scalar_vartime(black_box(*scalar));
                }

                out
            });
        });

        group.bench_function("p256_separate", |b| {
            b.iter(|| {
                let mut out = P256ProjectivePoint::IDENTITY;

                for (point, scalar) in p256_points.iter().zip(p256_scalars.iter()) {
                    out = out + (black_box(*point) * black_box(*scalar));
                }

                out
            });
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_group_double,
    bench_group_add,
    bench_group_mixed_add,
    bench_group_base_scalar_mul,
    bench_group_double_scalar_mul,
    bench_group_multi_scalar_mul
);
criterion_main!(benches);
