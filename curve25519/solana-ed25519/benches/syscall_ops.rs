//! The curve25519 syscall operations as `solana-curve25519` performs them:
//! validate a compressed point, and add or subtract two compressed points,
//! returning the compressed result. Each operation decompresses its inputs
//! (a square root per point) and compresses its output (an inversion or
//! inverse square root), which is where nearly all of the time goes.
//!
//! Every operation is measured on this crate and on upstream
//! `curve25519-dalek`, which `solana-curve25519` uses today. The two are
//! checked to agree before anything is timed.

use criterion::{Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::hint::black_box;
use std::time::Duration;

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x7379_7363_616c_6c73)
}

fn random_wide(rng: &mut StdRng) -> [u8; 64] {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    wide
}

mod ours {
    use solana_ed25519::edwards::{CompressedEdwardsY, EdwardsPoint};
    use solana_ed25519::ristretto::{CompressedRistretto, RistrettoPoint};
    use solana_ed25519::scalar::Scalar;

    pub fn edwards_point(wide: &[u8; 64]) -> [u8; 32] {
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order_wide(wide))
            .compress()
            .to_bytes()
    }
    pub fn ristretto_point(wide: &[u8; 64]) -> [u8; 32] {
        RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(wide))
            .compress()
            .to_bytes()
    }
    pub fn edwards_validate(p: &[u8; 32]) -> bool {
        CompressedEdwardsY(*p).decompress().is_some()
    }
    pub fn edwards_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn edwards_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }
    pub fn ristretto_validate(p: &[u8; 32]) -> bool {
        CompressedRistretto(*p).decompress().is_some()
    }
    pub fn ristretto_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn ristretto_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }

    // The syscall shapes using the Legendre-symbol validation, the paired
    // decompression and, for Edwards, the variable-time compression.
    pub fn edwards_validate_fast(p: &[u8; 32]) -> bool {
        CompressedEdwardsY(*p).decompresses_vartime()
    }
    pub fn edwards_add_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let (a, b) =
            CompressedEdwardsY::decompress_pair(&CompressedEdwardsY(*a), &CompressedEdwardsY(*b))?;
        Some((a + b).compress_vartime().to_bytes())
    }
    pub fn edwards_sub_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let (a, b) =
            CompressedEdwardsY::decompress_pair(&CompressedEdwardsY(*a), &CompressedEdwardsY(*b))?;
        Some((a - b).compress_vartime().to_bytes())
    }
    pub fn ristretto_add_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let (a, b) = CompressedRistretto::decompress_pair(
            &CompressedRistretto(*a),
            &CompressedRistretto(*b),
        )?;
        Some((a + b).compress().to_bytes())
    }
    pub fn ristretto_sub_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let (a, b) = CompressedRistretto::decompress_pair(
            &CompressedRistretto(*a),
            &CompressedRistretto(*b),
        )?;
        Some((a - b).compress().to_bytes())
    }
}

mod upstream {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;

    pub fn edwards_point(wide: &[u8; 64]) -> [u8; 32] {
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order_wide(wide))
            .compress()
            .to_bytes()
    }
    pub fn ristretto_point(wide: &[u8; 64]) -> [u8; 32] {
        RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(wide))
            .compress()
            .to_bytes()
    }
    pub fn edwards_validate(p: &[u8; 32]) -> bool {
        CompressedEdwardsY(*p).decompress().is_some()
    }
    pub fn edwards_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn edwards_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }
    pub fn ristretto_validate(p: &[u8; 32]) -> bool {
        CompressedRistretto(*p).decompress().is_some()
    }
    pub fn ristretto_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn ristretto_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }
}

fn bench_syscalls(c: &mut Criterion) {
    let mut rng = rng();
    let (wa, wb) = (random_wide(&mut rng), random_wide(&mut rng));
    let (ea, eb) = (ours::edwards_point(&wa), ours::edwards_point(&wb));
    let (ra, rb) = (ours::ristretto_point(&wa), ours::ristretto_point(&wb));
    // Random bytes: usually not a valid encoding, the rejection path.
    let mut junk = [0u8; 32];
    rng.fill_bytes(&mut junk);

    // Both libraries must agree on every input before timing.
    assert_eq!(ea, upstream::edwards_point(&wa));
    assert_eq!(ra, upstream::ristretto_point(&wa));
    assert!(ours::edwards_validate(&ea) && upstream::edwards_validate(&ea));
    assert!(ours::ristretto_validate(&ra) && upstream::ristretto_validate(&ra));
    assert_eq!(
        ours::edwards_validate(&junk),
        upstream::edwards_validate(&junk)
    );
    assert_eq!(
        ours::ristretto_validate(&junk),
        upstream::ristretto_validate(&junk)
    );
    assert_eq!(ours::edwards_add(&ea, &eb), upstream::edwards_add(&ea, &eb));
    assert_eq!(ours::edwards_sub(&ea, &eb), upstream::edwards_sub(&ea, &eb));
    assert_eq!(
        ours::ristretto_add(&ra, &rb),
        upstream::ristretto_add(&ra, &rb)
    );
    assert_eq!(
        ours::ristretto_sub(&ra, &rb),
        upstream::ristretto_sub(&ra, &rb)
    );
    assert!(ours::edwards_validate_fast(&ea));
    assert_eq!(
        ours::edwards_validate_fast(&junk),
        upstream::edwards_validate(&junk)
    );
    assert_eq!(
        ours::edwards_add_fast(&ea, &eb),
        upstream::edwards_add(&ea, &eb)
    );
    assert_eq!(
        ours::edwards_sub_fast(&ea, &eb),
        upstream::edwards_sub(&ea, &eb)
    );
    assert_eq!(
        ours::ristretto_add_fast(&ra, &rb),
        upstream::ristretto_add(&ra, &rb)
    );
    assert_eq!(
        ours::ristretto_sub_fast(&ra, &rb),
        upstream::ristretto_sub(&ra, &rb)
    );

    let mut g = c.benchmark_group("edwards");
    g.bench_function("validate", |b| {
        b.iter(|| ours::edwards_validate(black_box(&ea)))
    });
    g.bench_function("validate/upstream", |b| {
        b.iter(|| upstream::edwards_validate(black_box(&ea)))
    });
    g.bench_function("validate_invalid", |b| {
        b.iter(|| ours::edwards_validate(black_box(&junk)))
    });
    g.bench_function("add", |b| {
        b.iter(|| ours::edwards_add(black_box(&ea), black_box(&eb)))
    });
    g.bench_function("add/upstream", |b| {
        b.iter(|| upstream::edwards_add(black_box(&ea), black_box(&eb)))
    });
    g.bench_function("sub", |b| {
        b.iter(|| ours::edwards_sub(black_box(&ea), black_box(&eb)))
    });
    g.bench_function("sub/upstream", |b| {
        b.iter(|| upstream::edwards_sub(black_box(&ea), black_box(&eb)))
    });
    g.bench_function("validate_fast", |b| {
        b.iter(|| ours::edwards_validate_fast(black_box(&ea)))
    });
    g.bench_function("validate_invalid_fast", |b| {
        b.iter(|| ours::edwards_validate_fast(black_box(&junk)))
    });
    g.bench_function("add_fast", |b| {
        b.iter(|| ours::edwards_add_fast(black_box(&ea), black_box(&eb)))
    });
    g.bench_function("sub_fast", |b| {
        b.iter(|| ours::edwards_sub_fast(black_box(&ea), black_box(&eb)))
    });
    g.finish();

    let mut g = c.benchmark_group("ristretto");
    g.bench_function("validate", |b| {
        b.iter(|| ours::ristretto_validate(black_box(&ra)))
    });
    g.bench_function("validate/upstream", |b| {
        b.iter(|| upstream::ristretto_validate(black_box(&ra)))
    });
    g.bench_function("validate_invalid", |b| {
        b.iter(|| ours::ristretto_validate(black_box(&junk)))
    });
    g.bench_function("add", |b| {
        b.iter(|| ours::ristretto_add(black_box(&ra), black_box(&rb)))
    });
    g.bench_function("add/upstream", |b| {
        b.iter(|| upstream::ristretto_add(black_box(&ra), black_box(&rb)))
    });
    g.bench_function("sub", |b| {
        b.iter(|| ours::ristretto_sub(black_box(&ra), black_box(&rb)))
    });
    g.bench_function("sub/upstream", |b| {
        b.iter(|| upstream::ristretto_sub(black_box(&ra), black_box(&rb)))
    });
    g.bench_function("add_fast", |b| {
        b.iter(|| ours::ristretto_add_fast(black_box(&ra), black_box(&rb)))
    });
    g.bench_function("sub_fast", |b| {
        b.iter(|| ours::ristretto_sub_fast(black_box(&ra), black_box(&rb)))
    });
    g.finish();
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_syscalls
}
criterion_main!(benches);
