//! The curve25519 syscall operations as `solana-curve25519` performs them:
//! validate a compressed point, and add or subtract two compressed points,
//! returning the compressed result. Compare this crate's optimized helpers
//! with its decode/operate/encode path and upstream dalek on seeded corpora.
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
    pub fn edwards_validate_decompress(p: &[u8; 32]) -> bool {
        CompressedEdwardsY(*p).decompress().is_some()
    }
    pub fn edwards_add_decompress(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn edwards_sub_decompress(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedEdwardsY(*a).decompress()?;
        let b = CompressedEdwardsY(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }
    pub fn ristretto_validate(p: &[u8; 32]) -> bool {
        CompressedRistretto(*p).decompress().is_some()
    }
    pub fn ristretto_add_decompress(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a + b).compress().to_bytes())
    }
    pub fn ristretto_sub_decompress(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let a = CompressedRistretto(*a).decompress()?;
        let b = CompressedRistretto(*b).decompress()?;
        Some((a - b).compress().to_bytes())
    }

    // Optimized helpers used by the primary validation and group-op benchmarks.
    pub fn edwards_validate(p: &[u8; 32]) -> bool {
        CompressedEdwardsY(*p).decompresses()
    }
    pub fn edwards_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedEdwardsY(*a)
                .add_vartime(&CompressedEdwardsY(*b))?
                .to_bytes(),
        )
    }
    pub fn edwards_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedEdwardsY(*a)
                .sub_vartime(&CompressedEdwardsY(*b))?
                .to_bytes(),
        )
    }
    pub fn ristretto_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            CompressedRistretto(*a)
                .add_vartime(&CompressedRistretto(*b))?
                .to_bytes(),
        )
    }
    pub fn ristretto_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
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
        let ep = ours::edwards_point(&wide);
        let rp = ours::ristretto_point(&wide);
        assert_eq!(ep, upstream::edwards_point(&wide));
        assert_eq!(rp, upstream::ristretto_point(&wide));
        edwards.push(ep);
        ristretto.push(rp);
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
         $validate:ident, $add:ident, $add_decompress:ident,
         $sub:ident, $sub_decompress:ident $(, $validate_decompress:ident)?) => {{
            let identity = $compressed::identity().to_bytes();
            for (case, inputs) in [
                ("random", $points.as_slice()),
                ("invalid", $invalid.as_slice()),
                ("identity", core::slice::from_ref(&identity)),
            ] {
                for p in inputs {
                    let expected = upstream::$validate(p);
                    assert_eq!(ours::$validate(p), expected);
                    $(assert_eq!(ours::$validate_decompress(p), expected);)?
                }
                let mut g = c.benchmark_group(concat!($name, "/corpus/").to_owned() + case);
                bench_inputs(&mut g, "validate", inputs, ours::$validate);
                bench_inputs(&mut g, "validate_upstream", inputs, upstream::$validate);
                $(bench_inputs(&mut g, "validate_decompress", inputs, ours::$validate_decompress);)?
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
                    assert_eq!(ours::$add_decompress(a, b), upstream::$add(a, b));
                    assert_eq!(ours::$sub(a, b), upstream::$sub(a, b));
                    assert_eq!(ours::$sub_decompress(a, b), upstream::$sub(a, b));
                }
                let mut g = c.benchmark_group(concat!($name, "/corpus/").to_owned() + case);
                bench_inputs(&mut g, "add", inputs, |(a, b)| ours::$add(a, b));
                bench_inputs(&mut g, "add_decompress", inputs, |(a, b)| {
                    ours::$add_decompress(a, b)
                });
                bench_inputs(&mut g, "add_upstream", inputs, |(a, b)| {
                    upstream::$add(a, b)
                });
                bench_inputs(&mut g, "sub", inputs, |(a, b)| ours::$sub(a, b));
                bench_inputs(&mut g, "sub_decompress", inputs, |(a, b)| {
                    ours::$sub_decompress(a, b)
                });
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
        edwards_add,
        edwards_add_decompress,
        edwards_sub,
        edwards_sub_decompress,
        edwards_validate_decompress
    );
    curve!(
        "ristretto",
        ristretto,
        ristretto_invalid,
        CompressedRistretto,
        ristretto_validate,
        ristretto_add,
        ristretto_add_decompress,
        ristretto_sub,
        ristretto_sub_decompress
    );

    // A structured y with (y² - 1)(d*y² + 1) = 2^254 + 2^250.
    let structured: Encoding =
        hex::decode("7379fce5984ae7b06649cb0a9134e7439357b9c2fdeb244b527e77755233217f")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        ours::edwards_validate(&structured),
        upstream::edwards_validate(&structured)
    );
    assert_eq!(
        ours::edwards_validate_decompress(&structured),
        upstream::edwards_validate(&structured)
    );
    let mut g = c.benchmark_group("edwards/corpus/structured");
    bench_inputs(
        &mut g,
        "validate_decompress",
        &[structured],
        ours::edwards_validate_decompress,
    );
    bench_inputs(&mut g, "validate", &[structured], ours::edwards_validate);
    bench_inputs(
        &mut g,
        "validate_upstream",
        &[structured],
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
    targets = bench_corpus
}
criterion_main!(benches);
