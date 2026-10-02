//! The curve25519 syscall operations as `solana-curve25519` performs them:
//! validate a compressed point, and add or subtract two compressed points,
//! returning the compressed result. Each operation decompresses its inputs
//! (a square root per point) and compresses its output (an inversion or
//! inverse square root), which is where nearly all of the time goes.
//!
//! Every operation is measured on this crate and on upstream
//! `curve25519-dalek`, which `solana-curve25519` uses today. The two are
//! checked to agree before anything is timed.

use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
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
        Some(
            CompressedEdwardsY(*a)
                .add_vartime(&CompressedEdwardsY(*b))?
                .to_bytes(),
        )
    }
    pub fn edwards_sub_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedEdwardsY(*a)
                .sub_vartime(&CompressedEdwardsY(*b))?
                .to_bytes(),
        )
    }
    pub fn ristretto_add_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedRistretto(*a)
                .add_vartime(&CompressedRistretto(*b))?
                .to_bytes(),
        )
    }
    pub fn ristretto_sub_fast(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedRistretto(*a)
                .sub_vartime(&CompressedRistretto(*b))?
                .to_bytes(),
        )
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
    // Guaranteed invalid for both curves, so these measure rejection.
    let mut junk = [0u8; 32];
    loop {
        rng.fill_bytes(&mut junk);
        if !upstream::edwards_validate(&junk) && !upstream::ristretto_validate(&junk) {
            break;
        }
    }

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

// Cycle through a seeded corpus instead of repeatedly predicting the branches
// for one point. Setup and agreement checks are outside the timed region.
type Encoding = [u8; 32];
type Pair = (Encoding, Encoding);

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

fn bench_corpus(c: &mut Criterion) {
    use solana_ed25519::{
        edwards::CompressedEdwardsY, ristretto::CompressedRistretto, traits::Identity,
    };
    let mut rng = rng();
    let mut edwards = Vec::new();
    let mut ristretto = Vec::new();
    let mut edwards_invalid = Vec::new();
    let mut ristretto_invalid = Vec::new();
    for _ in 0..64 {
        let wide = random_wide(&mut rng);
        edwards.push(ours::edwards_point(&wide));
        ristretto.push(ours::ristretto_point(&wide));
        let mut bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut bytes);
            if !upstream::edwards_validate(&bytes) {
                edwards_invalid.push(bytes);
                break;
            }
        }
        loop {
            rng.fill_bytes(&mut bytes);
            if !upstream::ristretto_validate(&bytes) {
                ristretto_invalid.push(bytes);
                break;
            }
        }
    }

    macro_rules! curve {
        ($name:literal, $points:ident, $invalid:ident, $compressed:ident,
         $validate:ident, $validate_fast:ident, $add:ident, $add_fast:ident,
         $sub:ident, $sub_fast:ident) => {{
            let identity = $compressed::identity().to_bytes();
            for (case, inputs) in [
                ("random", $points.as_slice()),
                ("invalid", $invalid.as_slice()),
                ("identity", core::slice::from_ref(&identity)),
            ] {
                for p in inputs {
                    let expected = upstream::$validate(p);
                    assert_eq!(ours::$validate(p), expected);
                    assert_eq!(ours::$validate_fast(p), expected);
                }
                let mut g = c.benchmark_group(concat!($name, "/corpus/").to_owned() + case);
                bench_inputs(&mut g, "validate", inputs, ours::$validate);
                bench_inputs(&mut g, "validate_fast", inputs, ours::$validate_fast);
                bench_inputs(&mut g, "validate_upstream", inputs, upstream::$validate);
            }
            let random: Vec<Pair> = $points
                .iter()
                .enumerate()
                .map(|(i, a)| (*a, $points[(i + 1) % $points.len()]))
                .collect();
            let equal: Vec<Pair> = $points.iter().map(|a| (*a, *a)).collect();
            let opposite: Vec<Pair> = $points
                .iter()
                .map(|a| {
                    (
                        *a,
                        (-$compressed(*a).decompress().unwrap())
                            .compress()
                            .to_bytes(),
                    )
                })
                .collect();
            let identities: Vec<Pair> = $points
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    if i % 2 == 0 {
                        (*a, identity)
                    } else {
                        (identity, *a)
                    }
                })
                .chain(core::iter::once((identity, identity)))
                .collect();
            let invalid_first: Vec<Pair> = $invalid
                .iter()
                .zip(&$points)
                .map(|(a, b)| (*a, *b))
                .collect();
            let invalid_second: Vec<Pair> = invalid_first.iter().map(|(a, b)| (*b, *a)).collect();
            for (case, inputs) in [
                ("random", &random),
                ("equal", &equal),
                ("opposite", &opposite),
                ("identity", &identities),
                ("invalid_first", &invalid_first),
                ("invalid_second", &invalid_second),
            ] {
                for (a, b) in inputs {
                    assert_eq!(ours::$add(a, b), upstream::$add(a, b));
                    assert_eq!(ours::$add_fast(a, b), upstream::$add(a, b));
                    assert_eq!(ours::$sub(a, b), upstream::$sub(a, b));
                    assert_eq!(ours::$sub_fast(a, b), upstream::$sub(a, b));
                }
                let mut g = c.benchmark_group(concat!($name, "/corpus/").to_owned() + case);
                bench_inputs(&mut g, "add", inputs, |(a, b)| ours::$add(a, b));
                bench_inputs(&mut g, "add_fast", inputs, |(a, b)| ours::$add_fast(a, b));
                bench_inputs(&mut g, "add_upstream", inputs, |(a, b)| {
                    upstream::$add(a, b)
                });
                bench_inputs(&mut g, "sub", inputs, |(a, b)| ours::$sub(a, b));
                bench_inputs(&mut g, "sub_fast", inputs, |(a, b)| ours::$sub_fast(a, b));
                bench_inputs(&mut g, "sub_upstream", inputs, |(a, b)| {
                    upstream::$sub(a, b)
                });
            }
        }};
    }
    curve!(
        "edwards",
        edwards,
        edwards_invalid,
        CompressedEdwardsY,
        edwards_validate,
        edwards_validate_fast,
        edwards_add,
        edwards_add_fast,
        edwards_sub,
        edwards_sub_fast
    );
    curve!(
        "ristretto",
        ristretto,
        ristretto_invalid,
        CompressedRistretto,
        ristretto_validate,
        ristretto_validate,
        ristretto_add,
        ristretto_add_fast,
        ristretto_sub,
        ristretto_sub_fast
    );

    // y with (y² - 1)(d*y² + 1) = 2^254 + 2^250. This reached the
    // posdivsteps cap before the machine-word finishing optimization.
    let slow: Encoding =
        hex::decode("7379fce5984ae7b06649cb0a9134e7439357b9c2fdeb244b527e77755233217f")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        ours::edwards_validate_fast(&slow),
        upstream::edwards_validate(&slow)
    );
    let mut g = c.benchmark_group("edwards/corpus/structured");
    bench_inputs(&mut g, "validate", &[slow], ours::edwards_validate);
    bench_inputs(
        &mut g,
        "validate_fast",
        &[slow],
        ours::edwards_validate_fast,
    );
    bench_inputs(
        &mut g,
        "validate_upstream",
        &[slow],
        upstream::edwards_validate,
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
    targets = bench_syscalls, bench_corpus
}
criterion_main!(benches);
