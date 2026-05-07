#[cfg(feature = "std")]
use crate::ed_sigs::tests::small_order::SMALL_ORDER_SIGS;
use crate::{
    Scalar,
    ed_sigs::{Error, HEEA_PARAM_LENGTH, HEEAParam, Signature, SigningKey, VerificationKey},
    traits::HEEADecomposition,
};
#[cfg(feature = "std")]
use core::convert::TryFrom;
use sha2::{Sha512, digest::Update};

fn challenge_scalar(vk: &VerificationKey, signature: &Signature, msg: &[u8]) -> Scalar {
    Scalar::from_hash(
        Sha512::default()
            .chain(&signature.r_bytes()[..])
            .chain(vk.as_ref())
            .chain(msg),
    )
}

#[test]
fn test_verify_heea_invalid_signature() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);

    let msg = b"Original message";
    let signature = signing_key.sign(msg);

    // Try to verify with different message
    let wrong_msg = b"Different message";

    let result_default = verification_key.verify(&signature, wrong_msg);
    let result_zebra = verification_key.verify_zebra(&signature, wrong_msg);
    let result_dalek = verification_key.verify_dalek(&signature, wrong_msg);

    assert!(
        result_default.is_err(),
        "Default verification should fail for wrong message"
    );
    assert!(
        result_zebra.is_err(),
        "Zebra verification should fail for wrong message"
    );
    assert!(
        result_dalek.is_err(),
        "Dalek verification should fail for wrong message"
    );
}

#[test]
fn test_verify_heea_multiple_signatures() {
    let mut rng = rand::rng();

    for i in 0..100 {
        let signing_key = SigningKey::new(&mut rng);
        let verification_key = VerificationKey::from(&signing_key);

        let msg = format!("Message number {}", i);
        let signature = signing_key.sign(msg.as_bytes());

        let result_default = verification_key.verify(&signature, msg.as_bytes());
        let result_zebra = verification_key.verify_zebra(&signature, msg.as_bytes());
        let result_dalek = verification_key.verify_dalek(&signature, msg.as_bytes());

        assert!(
            result_default.is_ok(),
            "Default verification should succeed for signature {}",
            i
        );
        assert!(
            result_zebra.is_ok(),
            "Zebra verification should succeed for signature {}",
            i
        );
        assert!(
            result_dalek.is_ok(),
            "Dalek verification should succeed for signature {}",
            i
        );
    }
}

#[test]
fn test_default_verification_matches_zebra() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"default verification mode";
    let signature = signing_key.sign(msg);

    assert_eq!(
        verification_key.verify(&signature, msg),
        verification_key.verify_zebra(&signature, msg)
    );
}

#[test]
fn test_relayer_verify_with_precomputed_heea_params() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"relayer verification mode";
    let signature = signing_key.sign(msg);
    let heea_params =
        HEEAParam::try_from(challenge_scalar(&verification_key, &signature, msg).heea_decompose())
            .expect("HEEA decomposition should fit relayer parameter encoding");

    assert_eq!(
        verification_key.relayer_verify(&signature, msg, heea_params),
        verification_key.verify_zebra(&signature, msg)
    );
    assert_eq!(
        verification_key.relayer_verify(&signature, b"wrong message", heea_params),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn test_relayer_verify_rejects_zero_heea_params() {
    let bytes = [0u8; HEEA_PARAM_LENGTH];

    assert_eq!(HEEAParam::try_from(bytes), Err(Error::InvalidSignature));
}

#[test]
fn test_heea_params_roundtrip_33_byte_encoding() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"relayer param serialization";
    let signature = signing_key.sign(msg);
    let heea_params =
        HEEAParam::try_from(challenge_scalar(&verification_key, &signature, msg).heea_decompose())
            .expect("HEEA decomposition should fit relayer parameter encoding");
    let bytes = heea_params.to_bytes();

    assert_eq!(bytes.len(), HEEA_PARAM_LENGTH);
    assert_eq!(HEEAParam::try_from(bytes), Ok(heea_params));
    assert_eq!(
        verification_key.relayer_verify(&signature, msg, heea_params),
        verification_key.relayer_verify(
            &signature,
            msg,
            HEEAParam::try_from(bytes.as_ref())
                .expect("serialized HEEA parameters should deserialize")
        )
    );
}

#[test]
fn test_relayer_verify_rejects_full_size_heea_params() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);

    for i in 0..1000 {
        let msg = format!("full-size relayer params {}", i);
        let signature = signing_key.sign(msg.as_bytes());
        let h = challenge_scalar(&verification_key, &signature, msg.as_bytes());

        if h.as_bytes()[16..32].iter().any(|&byte| byte != 0) {
            assert_eq!(
                HEEAParam::try_from((h, Scalar::ONE, false)),
                Err(Error::InvalidSignature)
            );
            return;
        }
    }

    panic!("failed to find a full-size challenge scalar");
}

#[test]
fn test_relayer_verify_dalek_with_precomputed_heea_params() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"dalek relayer verification mode";
    let signature = signing_key.sign(msg);
    let heea_params =
        HEEAParam::try_from(challenge_scalar(&verification_key, &signature, msg).heea_decompose())
            .expect("HEEA decomposition should fit relayer parameter encoding");

    assert_eq!(
        verification_key.relayer_verify_dalek(&signature, msg, heea_params),
        verification_key.verify_dalek(&signature, msg)
    );
    assert_eq!(
        verification_key.relayer_verify_dalek(&signature, b"wrong message", heea_params),
        Err(Error::InvalidSignature)
    );
}

#[cfg(feature = "std")]
#[test]
fn test_verify_dalek_matches_legacy_edge_cases() {
    for case in SMALL_ORDER_SIGS.iter() {
        let sig = Signature::from(case.sig_bytes);
        let vk = VerificationKey::try_from(case.vk_bytes).expect("test vector key should parse");
        let heea_params =
            HEEAParam::try_from(challenge_scalar(&vk, &sig, b"Zcash").heea_decompose())
                .expect("HEEA decomposition should fit relayer parameter encoding");
        let result = vk.verify_dalek(&sig, b"Zcash");

        assert_eq!(
            result.is_ok(),
            case.valid_legacy,
            "dalek-compatible verification mismatch for vk={} sig={}",
            hex::encode(case.vk_bytes),
            hex::encode(case.sig_bytes)
        );
        assert_eq!(vk.relayer_verify_dalek(&sig, b"Zcash", heea_params), result);
    }
}
