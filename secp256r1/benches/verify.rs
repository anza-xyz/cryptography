use criterion::{Criterion, black_box, criterion_group, criterion_main};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Public,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, hazmat::PrehashVerifier},
};
use secp256r1::{Signature, VerifyingKey as RustVerifyingKey};
use sha2::{Digest as _, Sha256};

const MESSAGE: &[u8] = b"secp256r1 verification benchmark message";

struct BenchFixture {
    digest: [u8; 32],
    message: &'static [u8],
    rust_signature: Signature,
    openssl_signature: EcdsaSig,
    p256_signature: P256Signature,
    public_key_sec1: Vec<u8>,
    signature_der: Vec<u8>,
}

impl BenchFixture {
    fn new() -> Self {
        let secret = [7u8; 32];
        let signing_key = SigningKey::from_slice(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();
        let p256_signature: P256Signature = signing_key.sign(MESSAGE);
        let signature_der = p256_signature.to_der().as_bytes().to_vec();
        let signature_bytes = p256_signature.to_bytes();
        let rust_signature = Signature::from_scalars(
            signature_bytes[..32].try_into().unwrap(),
            signature_bytes[32..].try_into().unwrap(),
        )
        .unwrap();
        let digest = Sha256::digest(MESSAGE).into();
        let openssl_signature = EcdsaSig::from_der(&signature_der).unwrap();

        Self {
            digest,
            message: MESSAGE,
            rust_signature,
            openssl_signature,
            p256_signature,
            public_key_sec1: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            signature_der,
        }
    }
}

fn sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

struct P256Comparison {
    verifying_key: VerifyingKey,
}

impl P256Comparison {
    fn from_sec1_public_key(public_key_sec1: &[u8]) -> Self {
        Self {
            verifying_key: VerifyingKey::from_sec1_bytes(public_key_sec1).unwrap(),
        }
    }

    fn verify_prehashed_signature(&self, digest: &[u8], signature: &P256Signature) -> bool {
        self.verifying_key.verify_prehash(digest, signature).is_ok()
    }

    fn verify_prehashed_der(&self, digest: &[u8], signature_der: &[u8]) -> bool {
        let signature = P256Signature::from_der(signature_der).unwrap();
        self.verify_prehashed_signature(digest, &signature)
    }
}

struct OpenSslComparison {
    ec_key: EcKey<Public>,
}

impl OpenSslComparison {
    fn from_sec1_public_key(public_key_sec1: &[u8]) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, public_key_sec1, &mut context).unwrap();
        let ec_key = EcKey::from_public_key(&group, &point).unwrap();

        Self { ec_key }
    }

    fn verify_prehashed_signature(&self, digest: &[u8], signature: &EcdsaSig) -> bool {
        signature.verify(digest, &self.ec_key).unwrap()
    }

    fn verify_prehashed_der(&self, digest: &[u8], signature_der: &[u8]) -> bool {
        let signature = EcdsaSig::from_der(signature_der).unwrap();
        self.verify_prehashed_signature(digest, &signature)
    }
}

fn bench_prehashed_preparsed(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let p256_verifier = P256Comparison::from_sec1_public_key(&fixture.public_key_sec1);
    let rust_verifier = RustVerifyingKey::from_sec1_bytes(&fixture.public_key_sec1).unwrap();
    let openssl_verifier = OpenSslComparison::from_sec1_public_key(&fixture.public_key_sec1);

    let mut group = c.benchmark_group("secp256r1_verify_prehashed_preparsed");

    group.bench_function("p256", |b| {
        b.iter(|| {
            assert!(p256_verifier.verify_prehashed_signature(
                black_box(&fixture.digest),
                black_box(&fixture.p256_signature)
            ));
        });
    });

    group.bench_function("rust", |b| {
        b.iter(|| {
            assert!(
                rust_verifier
                    .verify_prehash(
                        black_box(&fixture.digest),
                        black_box(&fixture.rust_signature)
                    )
                    .is_ok()
            );
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            assert!(openssl_verifier.verify_prehashed_signature(
                black_box(&fixture.digest),
                black_box(&fixture.openssl_signature)
            ));
        });
    });

    group.finish();
}

fn bench_prehashed_der(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let p256_verifier = P256Comparison::from_sec1_public_key(&fixture.public_key_sec1);
    let rust_verifier = RustVerifyingKey::from_sec1_bytes(&fixture.public_key_sec1).unwrap();
    let openssl_verifier = OpenSslComparison::from_sec1_public_key(&fixture.public_key_sec1);

    let mut group = c.benchmark_group("secp256r1_verify_prehashed_der");

    group.bench_function("p256", |b| {
        b.iter(|| {
            assert!(p256_verifier.verify_prehashed_der(
                black_box(&fixture.digest),
                black_box(&fixture.signature_der)
            ));
        });
    });

    group.bench_function("rust", |b| {
        b.iter(|| {
            assert!(
                rust_verifier
                    .verify_prehashed_der(
                        black_box(&fixture.digest),
                        black_box(&fixture.signature_der)
                    )
                    .is_ok()
            );
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            assert!(openssl_verifier.verify_prehashed_der(
                black_box(&fixture.digest),
                black_box(&fixture.signature_der)
            ));
        });
    });

    group.finish();
}

fn bench_message_sha256_preparsed(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let p256_verifier = P256Comparison::from_sec1_public_key(&fixture.public_key_sec1);
    let rust_verifier = RustVerifyingKey::from_sec1_bytes(&fixture.public_key_sec1).unwrap();
    let openssl_verifier = OpenSslComparison::from_sec1_public_key(&fixture.public_key_sec1);

    let mut group = c.benchmark_group("secp256r1_verify_message_sha256_preparsed");

    group.bench_function("p256", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(p256_verifier.verify_prehashed_signature(
                black_box(&digest),
                black_box(&fixture.p256_signature)
            ));
        });
    });

    group.bench_function("rust", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(
                rust_verifier
                    .verify_prehash(black_box(&digest), black_box(&fixture.rust_signature))
                    .is_ok()
            );
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(openssl_verifier.verify_prehashed_signature(
                black_box(&digest),
                black_box(&fixture.openssl_signature)
            ));
        });
    });

    group.finish();
}

fn bench_message_sha256_der(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let p256_verifier = P256Comparison::from_sec1_public_key(&fixture.public_key_sec1);
    let rust_verifier = RustVerifyingKey::from_sec1_bytes(&fixture.public_key_sec1).unwrap();
    let openssl_verifier = OpenSslComparison::from_sec1_public_key(&fixture.public_key_sec1);

    let mut group = c.benchmark_group("secp256r1_verify_message_sha256_der");

    group.bench_function("p256", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(
                p256_verifier
                    .verify_prehashed_der(black_box(&digest), black_box(&fixture.signature_der))
            );
        });
    });

    group.bench_function("rust", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(
                rust_verifier
                    .verify_prehashed_der(black_box(&digest), black_box(&fixture.signature_der))
                    .is_ok()
            );
        });
    });

    group.bench_function("openssl", |b| {
        b.iter(|| {
            let digest = sha256(black_box(fixture.message));
            assert!(
                openssl_verifier
                    .verify_prehashed_der(black_box(&digest), black_box(&fixture.signature_der))
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_prehashed_preparsed,
    bench_prehashed_der,
    bench_message_sha256_preparsed,
    bench_message_sha256_der
);
criterion_main!(benches);
