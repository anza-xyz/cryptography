use criterion::{Criterion, black_box, criterion_group, criterion_main};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Private,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner},
};
use rand_core::{CryptoRng, Error as RngError, RngCore};
use secp256r1::SigningKey;
use sha2::{Digest as _, Sha256};

const MESSAGE: &[u8] = b"secp256r1 verification benchmark message";
const SECRET: [u8; 32] = [7u8; 32];

struct Fixture {
    digest: [u8; 32],
    rust_key: SigningKey,
    p256_key: P256SigningKey,
    openssl_key: EcKey<Private>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            digest: Sha256::digest(MESSAGE).into(),
            rust_key: SigningKey::from_slice(&SECRET).unwrap(),
            p256_key: P256SigningKey::from_slice(&SECRET).unwrap(),
            openssl_key: openssl_key_from_secret(),
        }
    }
}

#[derive(Clone, Copy)]
struct BenchRng {
    state: u64,
}

impl BenchRng {
    fn new() -> Self {
        Self {
            state: 0x243f_6a88_85a3_08d3,
        }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl RngCore for BenchRng {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next().to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for BenchRng {}

fn openssl_key_from_secret() -> EcKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_key = BigNum::from_slice(&SECRET).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut public_key = EcPoint::new(&group).unwrap();
    public_key
        .mul_generator2(&group, &private_key, &mut context)
        .unwrap();

    EcKey::from_private_components(&group, &private_key, &public_key).unwrap()
}

fn bench_keygen(c: &mut Criterion) {
    let openssl_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut rust_rng = BenchRng::new();
    let mut p256_rng = BenchRng::new();
    let mut group = c.benchmark_group("secp256r1_keygen");

    group.bench_function("rust", |b| {
        b.iter(|| SigningKey::random(black_box(&mut rust_rng)));
    });

    group.bench_function("p256", |b| {
        b.iter(|| P256SigningKey::random(black_box(&mut p256_rng)));
    });

    group.bench_function("openssl", |b| {
        b.iter(|| EcKey::generate(black_box(&openssl_group)).unwrap());
    });

    group.finish();
}

fn bench_sign_prehashed(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_sign_prehashed");

    group.bench_function("rust", |b| {
        b.iter(|| {
            let signature = fixture
                .rust_key
                .sign_prehash(black_box(&fixture.digest))
                .unwrap();
            black_box(signature);
        });
    });

    group.bench_function("p256", |b| {
        b.iter(|| {
            let signature: P256Signature = fixture
                .p256_key
                .sign_prehash(black_box(&fixture.digest))
                .unwrap();
            black_box(signature);
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            let signature =
                EcdsaSig::sign(black_box(&fixture.digest), black_box(&fixture.openssl_key))
                    .unwrap();
            black_box(signature);
        });
    });

    group.finish();
}

fn bench_sign_message_sha256(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut group = c.benchmark_group("secp256r1_sign_message_sha256");

    group.bench_function("rust", |b| {
        b.iter(|| black_box(fixture.rust_key.sign(black_box(MESSAGE))));
    });

    group.bench_function("p256", |b| {
        b.iter(|| {
            let signature: P256Signature = fixture.p256_key.sign(black_box(MESSAGE));
            black_box(signature);
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            let digest: [u8; 32] = Sha256::digest(black_box(MESSAGE)).into();
            let signature =
                EcdsaSig::sign(black_box(&digest), black_box(&fixture.openssl_key)).unwrap();
            black_box(signature);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign_prehashed,
    bench_sign_message_sha256
);
criterion_main!(benches);
