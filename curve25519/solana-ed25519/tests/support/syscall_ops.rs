//! Seeded syscall inputs and adapters shared by benchmarks and agreement tests.
use rand::{Rng, SeedableRng, rngs::StdRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x7379_7363_616c_6c73)
}

fn random_wide(rng: &mut StdRng) -> [u8; 64] {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    wide
}

pub mod ours {
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
        CompressedEdwardsY(*p).is_valid()
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

pub mod upstream {
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

pub type Encoding = [u8; 32];
pub type Pair = (Encoding, Encoding);

pub struct Corpus {
    pub validation: Vec<(&'static str, Vec<Encoding>)>,
    pub pairs: Vec<(&'static str, Vec<Pair>)>,
}

impl Corpus {
    fn new(
        point: fn(&[u8; 64]) -> Encoding,
        upstream_point: fn(&[u8; 64]) -> Encoding,
        validate: fn(&Encoding) -> bool,
        prepare_invalid: fn(&mut Encoding) -> bool,
        identity: Encoding,
        negate: fn(&Encoding) -> Encoding,
    ) -> Self {
        let mut rng = rng();
        let mut points = Vec::new();
        let mut invalid = Vec::new();
        for _ in 0..64 {
            let wide = random_wide(&mut rng);
            let p = point(&wide);
            assert_eq!(p, upstream_point(&wide));
            points.push(p);
            loop {
                let mut bytes = [0; 32];
                rng.fill_bytes(&mut bytes);
                if prepare_invalid(&mut bytes) && !validate(&bytes) {
                    invalid.push(bytes);
                    break;
                }
            }
        }
        let pairs = vec![
            (
                "random",
                points
                    .iter()
                    .enumerate()
                    .map(|(i, a)| (*a, points[(i + 1) % points.len()]))
                    .collect(),
            ),
            ("equal", points.iter().map(|a| (*a, *a)).collect()),
            ("opposite", points.iter().map(|a| (*a, negate(a))).collect()),
            (
                "identity",
                points
                    .iter()
                    .flat_map(|a| [(*a, identity), (identity, *a)])
                    .chain(core::iter::once((identity, identity)))
                    .collect(),
            ),
            (
                "invalid_first",
                invalid.iter().zip(&points).map(|(a, b)| (*a, *b)).collect(),
            ),
            (
                "invalid_second",
                points.iter().zip(&invalid).map(|(a, b)| (*a, *b)).collect(),
            ),
        ];
        Self {
            validation: vec![
                ("random", points),
                ("invalid", invalid),
                ("identity", vec![identity]),
            ],
            pairs,
        }
    }

    pub fn edwards() -> Self {
        use solana_ed25519::{edwards::CompressedEdwardsY, traits::Identity};
        let mut corpus = Self::new(
            ours::edwards_point,
            upstream::edwards_point,
            upstream::edwards_validate,
            |_| true,
            CompressedEdwardsY::identity().to_bytes(),
            |a| {
                (-CompressedEdwardsY(*a).decompress().unwrap())
                    .compress()
                    .to_bytes()
            },
        );
        // A structured y with (y² - 1)(d*y² + 1) = 2^254 + 2^250.
        let structured =
            hex::decode("7379fce5984ae7b06649cb0a9134e7439357b9c2fdeb244b527e77755233217f")
                .unwrap()
                .try_into()
                .unwrap();
        corpus.validation.push(("structured", vec![structured]));
        corpus
    }

    pub fn ristretto() -> Self {
        use solana_ed25519::{ristretto::CompressedRistretto, traits::Identity};
        Self::new(
            ours::ristretto_point,
            upstream::ristretto_point,
            upstream::ristretto_validate,
            |bytes| {
                // Reach the inverse-square-root step: s must be nonnegative
                // (even) and canonically encoded. Clearing the top bit alone
                // still leaves the 19 encodings at or above p = 2^255 - 19.
                bytes[0] &= 0xfe;
                bytes[31] &= 0x7f;
                let mut p = [0xff; 32];
                p[0] = 0xed;
                p[31] = 0x7f;
                bytes.iter().rev().lt(p.iter().rev())
            },
            CompressedRistretto::identity().to_bytes(),
            |a| {
                (-CompressedRistretto(*a).decompress().unwrap())
                    .compress()
                    .to_bytes()
            },
        )
    }
}

pub fn check_validation(
    corpus: &Corpus,
    validate: impl Fn(&Encoding) -> bool,
    reference: impl Fn(&Encoding) -> bool,
) {
    for (case, inputs) in &corpus.validation {
        for (index, input) in inputs.iter().enumerate() {
            assert_eq!(validate(input), reference(input), "{case}[{index}]");
        }
    }
}

pub fn check_group_op(
    corpus: &Corpus,
    apply: impl Fn(&Encoding, &Encoding) -> Option<Encoding>,
    reference: impl Fn(&Encoding, &Encoding) -> Option<Encoding>,
) {
    for (case, inputs) in &corpus.pairs {
        for (index, (a, b)) in inputs.iter().enumerate() {
            assert_eq!(apply(a, b), reference(a, b), "{case}[{index}]");
        }
    }
}
