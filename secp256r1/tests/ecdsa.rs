use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Verifier as OpenSslVerifier,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey, VerifyingKey, signature::Signer as _,
    signature::Verifier as _, signature::hazmat::PrehashVerifier,
};
use secp256r1::{
    Error, Signature, SigningKey as RustSigningKey, VerifyingKey as RustVerifyingKey,
    group::{AffinePoint, ProjectivePoint},
    scalar::Scalar,
};
use sha2::{Digest as _, Sha256};

const MESSAGE: &[u8] = b"secp256r1 verification benchmark message";
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let secret = [7u8; 32];
    let signing_key = SigningKey::from_slice(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();
    let signature: P256Signature = signing_key.sign(MESSAGE);

    (
        verifying_key.to_encoded_point(false).as_bytes().to_vec(),
        signature.to_der().as_bytes().to_vec(),
    )
}

fn sample_bytes<const N: usize>(mut seed: u64) -> [u8; N] {
    let mut bytes = [0u8; N];

    for chunk in bytes.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        chunk.copy_from_slice(&seed.to_be_bytes()[..chunk.len()]);
    }

    bytes
}

fn sample_secret(seed: u64) -> [u8; 32] {
    let mut secret = sample_bytes(seed);

    // Keep the sample strictly below the group order without rejection.
    secret[0] &= 0x7f;
    if secret.iter().all(|byte| *byte == 0) {
        secret[31] = 1;
    }

    secret
}

fn openssl_private_key(secret: &[u8; 32]) -> EcKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_key = BigNum::from_slice(secret).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut public_key = EcPoint::new(&group).unwrap();
    public_key
        .mul_generator2(&group, &private_key, &mut context)
        .unwrap();

    EcKey::from_private_components(&group, &private_key, &public_key).unwrap()
}

fn openssl_verifies(public_key: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, public_key, &mut context).unwrap();
    let ec_key = EcKey::from_public_key(&group, &point).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &pkey).unwrap();

    verifier.update(message).unwrap();
    verifier.verify(signature_der).unwrap()
}

fn small_signature_der() -> Vec<u8> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[31] = 1;
    s[31] = 2;

    Signature::from_scalars(r, s)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec()
}

fn order_plus_u32(value: u32) -> ([u8; 32], [u8; 32]) {
    let mut scalar = [0u8; 32];
    scalar[28..32].copy_from_slice(&value.to_be_bytes());

    let mut x = ORDER;
    let mut carry = value as u64;
    for byte in x.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xff);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }

    assert_eq!(carry, 0);
    (scalar, x)
}

#[test]
fn p256_verifies_der_signature() {
    let (public_key, signature_der) = fixture();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
    let signature = P256Signature::from_der(&signature_der).unwrap();

    assert!(verifying_key.verify(MESSAGE, &signature).is_ok());
}

#[test]
fn openssl_verifies_der_signature() {
    let (public_key, signature_der) = fixture();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, &public_key, &mut context).unwrap();
    let ec_key = EcKey::from_public_key(&group, &point).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &pkey).unwrap();

    verifier.update(MESSAGE).unwrap();

    assert!(verifier.verify(&signature_der).unwrap());
}

#[test]
fn verifying_key_verifies_der_signature() {
    let (public_key, signature) = fixture();
    let verifying_key = RustVerifyingKey::from_sec1_bytes(&public_key).unwrap();
    let digest = Sha256::digest(MESSAGE);

    assert!(
        verifying_key
            .verify_prehashed_der(&digest, &signature)
            .is_ok()
    );
}

#[test]
fn top_level_verifying_key_verifies_preparsed_signature() {
    let (public_key, signature_der) = fixture();
    let signature = Signature::from_der(&signature_der).unwrap();
    let verifying_key = RustVerifyingKey::from_sec1_bytes(&public_key).unwrap();
    let digest = Sha256::digest(MESSAGE);

    assert!(verifying_key.verify_prehash(&digest, &signature).is_ok());
}

#[test]
fn signing_key_derives_same_public_key_as_p256() {
    let secret = [7u8; 32];
    let signing_key = RustSigningKey::from_slice(&secret).unwrap();
    let p256_signing_key = SigningKey::from_slice(&secret).unwrap();

    assert_eq!(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
        p256_signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
    );
}

#[test]
fn signing_key_debug_redacts_secret() {
    let signing_key = RustSigningKey::from_slice(&[7u8; 32]).unwrap();
    let debug = format!("{signing_key:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("secret: Scalar"));
}

#[test]
fn signing_key_signs_and_verifies_message() {
    let secret = [7u8; 32];
    let signing_key = RustSigningKey::from_slice(&secret).unwrap();
    let signature = signing_key.sign(MESSAGE);

    assert!(
        signing_key
            .verifying_key()
            .verify(MESSAGE, &signature)
            .is_ok()
    );
}

#[test]
fn signing_key_signs_and_verifies_prehash() {
    let secret = [7u8; 32];
    let signing_key = RustSigningKey::from_slice(&secret).unwrap();
    let digest = Sha256::digest(MESSAGE);
    let signature = signing_key.sign_prehash(&digest).unwrap();

    assert!(
        signing_key
            .verifying_key()
            .verify_prehash(&digest, &signature)
            .is_ok()
    );
}

#[test]
fn compressed_sec1_public_key_round_trips() {
    let signing_key = RustSigningKey::from_slice(&[7u8; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_encoded_point(true);
    let reparsed = RustVerifyingKey::from_sec1_bytes(compressed.as_bytes()).unwrap();

    assert_eq!(
        reparsed.to_encoded_point(false).as_bytes(),
        verifying_key.to_encoded_point(false).as_bytes()
    );

    let p256_verifying_key = VerifyingKey::from_sec1_bytes(compressed.as_bytes()).unwrap();
    assert_eq!(
        p256_verifying_key.to_encoded_point(false).as_bytes(),
        verifying_key.to_encoded_point(false).as_bytes()
    );
}

#[test]
fn malformed_compressed_sec1_public_key_is_rejected() {
    let signing_key = RustSigningKey::from_slice(&[7u8; 32]).unwrap();
    let mut compressed = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    compressed[0] = 0x05;

    assert!(RustVerifyingKey::from_sec1_bytes(&compressed).is_err());
}

#[test]
fn p256_verifies_signature() {
    let secret = [7u8; 32];
    let signing_key = RustSigningKey::from_slice(&secret).unwrap();
    let p256_signing_key = SigningKey::from_slice(&secret).unwrap();
    let signature = signing_key.sign(MESSAGE);
    let p256_signature = P256Signature::from_slice(&signature.to_bytes()).unwrap();

    assert!(
        p256_signing_key
            .verifying_key()
            .verify(MESSAGE, &p256_signature)
            .is_ok()
    );
}

#[test]
fn strict_der_accepts_required_integer_leading_zero() {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[0] = 0x80;
    s[31] = 1;
    let signature = Signature::from_scalars(r, s).unwrap();
    let der = signature.to_der();

    assert_eq!(der.as_bytes()[3], 33);
    assert_eq!(Signature::from_der(der.as_bytes()).unwrap(), signature);
}

#[test]
fn strict_der_rejects_long_form_short_sequence_length() {
    let der = small_signature_der();
    let mut encoded = Vec::with_capacity(der.len() + 1);
    encoded.extend_from_slice(&[0x30, 0x81, der[1]]);
    encoded.extend_from_slice(&der[2..]);

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_long_form_short_integer_length() {
    let encoded = [0x30, 0x07, 0x02, 0x81, 0x01, 0x01, 0x02, 0x01, 0x02];

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_unnecessary_integer_leading_zero() {
    let encoded = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02];

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_negative_integer_encoding() {
    let mut encoded = vec![0x30, 0x25, 0x02, 0x20, 0x80];
    encoded.extend_from_slice(&[0u8; 31]);
    encoded.extend_from_slice(&[0x02, 0x01, 0x01]);

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_oversized_integer() {
    let mut encoded = vec![0x30, 0x26, 0x02, 0x21, 0x01];
    encoded.extend_from_slice(&[0u8; 32]);
    encoded.extend_from_slice(&[0x02, 0x01, 0x01]);

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_wrong_integer_tag_order() {
    let encoded = [0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02];

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_trailing_sequence_data() {
    let encoded = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00];

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn strict_der_rejects_outer_trailing_data() {
    let mut encoded = small_signature_der();
    encoded.push(0);

    assert!(Signature::from_der(&encoded).is_err());
}

#[test]
fn invalid_signature_returns_invalid_signature_error() {
    let signing_key = RustSigningKey::from_slice(&[7u8; 32]).unwrap();
    let digest = Sha256::digest(MESSAGE);
    let mut signature_bytes = signing_key.sign_prehash(&digest).unwrap().to_bytes();
    signature_bytes[63] ^= 1;
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    let signature_der = signature.to_der();
    let verifying_key = signing_key.verifying_key();

    assert!(matches!(
        verifying_key.verify_prehash(&digest, &signature),
        Err(Error::InvalidSignature)
    ));
    assert!(matches!(
        verifying_key.verify_prehashed_der(&digest, signature_der.as_bytes()),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn verification_accepts_signature_when_x_coordinate_exceeds_order() {
    let (r, point) = (1u32..=1024)
        .find_map(|candidate| {
            let (r, x) = order_plus_u32(candidate);
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&x);
            AffinePoint::from_sec1_compressed(compressed).map(|point| (r, point))
        })
        .expect("test range contains a curve point with x >= n");
    let r_inverse = Scalar::from_be_bytes(r).unwrap().invert().unwrap();
    let public_key = ProjectivePoint::mul_affine_scalar_vartime(point, r_inverse.to_be_bytes())
        .to_affine()
        .to_sec1_uncompressed()
        .unwrap();
    let verifying_key = RustVerifyingKey::from_sec1_bytes(&public_key).unwrap();
    let mut s = [0u8; 32];
    s[31] = 1;
    let signature = Signature::from_scalars(r, s).unwrap();

    assert!(verifying_key.verify_prehash(&[0u8; 32], &signature).is_ok());
}

#[test]
fn openssl_verifies_signature_der() {
    let secret = [7u8; 32];
    let signing_key = RustSigningKey::from_slice(&secret).unwrap();
    let signature = signing_key.sign(MESSAGE);
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, public_key.as_bytes(), &mut context).unwrap();
    let ec_key = EcKey::from_public_key(&group, &point).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &pkey).unwrap();

    verifier.update(MESSAGE).unwrap();

    assert!(verifier.verify(signature.to_der().as_bytes()).unwrap());
}

#[test]
fn random_signing_key_signs_and_verifies() {
    let mut rng = rand_core::OsRng;
    let signing_key = RustSigningKey::random(&mut rng);
    let signature = signing_key.sign(MESSAGE);

    assert!(
        signing_key
            .verifying_key()
            .verify(MESSAGE, &signature)
            .is_ok()
    );
}

#[test]
fn randomized_public_keys_match_p256() {
    for seed in 1..=64 {
        let secret = sample_secret(seed);
        let signing_key = RustSigningKey::from_slice(&secret).unwrap();
        let p256_signing_key = SigningKey::from_slice(&secret).unwrap();

        assert_eq!(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
            p256_signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
            "seed {seed}"
        );
    }
}

#[test]
fn randomized_signatures_verify_across_implementations() {
    for seed in 1..=32 {
        let secret = sample_secret(seed);
        let message = sample_bytes::<113>(seed ^ 0xa5a5_a5a5_a5a5_a5a5);
        let signing_key = RustSigningKey::from_slice(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false);
        let p256_signing_key = SigningKey::from_slice(&secret).unwrap();
        let p256_verifying_key = p256_signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let p256_signature = P256Signature::from_slice(&signature.to_bytes()).unwrap();
        assert!(
            p256_verifying_key.verify(&message, &p256_signature).is_ok(),
            "p256 rejected our signature for seed {seed}"
        );
        assert!(
            openssl_verifies(
                public_key.as_bytes(),
                &message,
                signature.to_der().as_bytes()
            ),
            "OpenSSL rejected our signature for seed {seed}"
        );

        let p256_signature: P256Signature = p256_signing_key.sign(&message);
        let signature = Signature::from_slice(&p256_signature.to_bytes()).unwrap();
        assert!(
            verifying_key.verify(&message, &signature).is_ok(),
            "we rejected p256 signature for seed {seed}"
        );
        assert!(
            openssl_verifies(
                public_key.as_bytes(),
                &message,
                p256_signature.to_der().as_bytes(),
            ),
            "OpenSSL rejected p256 signature for seed {seed}"
        );
    }
}

#[test]
fn randomized_openssl_prehash_signatures_verify_with_rust_and_p256() {
    for seed in 1..=16 {
        let secret = sample_secret(seed);
        let digest = Sha256::digest(sample_bytes::<97>(seed ^ 0x5a5a_5a5a_5a5a_5a5a));
        let signing_key = RustSigningKey::from_slice(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();
        let p256_signing_key = SigningKey::from_slice(&secret).unwrap();
        let openssl_key = openssl_private_key(&secret);
        let openssl_signature = EcdsaSig::sign(&digest, &openssl_key).unwrap();
        let signature_der = openssl_signature.to_der().unwrap();

        assert!(
            verifying_key
                .verify_prehashed_der(&digest, &signature_der)
                .is_ok(),
            "we rejected OpenSSL signature for seed {seed}"
        );

        let p256_signature = P256Signature::from_der(&signature_der).unwrap();
        assert!(
            p256_signing_key
                .verifying_key()
                .verify_prehash(&digest, &p256_signature)
                .is_ok(),
            "p256 rejected OpenSSL signature for seed {seed}"
        );
    }
}
