use crate::constants;
#[cfg(feature = "std")]
use crate::ed_sigs::tests::small_order::SMALL_ORDER_SIGS;
use crate::ed_sigs::{Error, Signature, SigningKey, VerificationKey};
use crate::edwards::CompressedEdwardsY;
use crate::scalar::Scalar;
#[cfg(feature = "std")]
use core::convert::TryFrom;

#[test]
fn test_verify_zebra_invalid_signature() {
    let signing_key = SigningKey::from([1u8; 32]);
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
fn test_verify_zebra_multiple_signatures() {
    for i in 0..100 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        let signing_key = SigningKey::from(seed);
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
    let signing_key = SigningKey::from([2u8; 32]);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"default verification mode";
    let signature = signing_key.sign(msg);

    assert_eq!(
        verification_key.verify(&signature, msg),
        verification_key.verify_zebra(&signature, msg)
    );
}

#[test]
fn test_signature_verifier_trait_impl() {
    let signing_key = SigningKey::from([3u8; 32]);
    let verification_key = VerificationKey::from(&signing_key);
    let msg = b"signature::Verifier trait path";
    let signature = signing_key.sign(msg);

    assert!(
        ed25519::signature::Verifier::verify(&verification_key, msg, &signature).is_ok(),
        "trait-based verification should accept a valid signature"
    );
    assert!(
        ed25519::signature::Verifier::verify(&verification_key, b"wrong message", &signature)
            .is_err(),
        "trait-based verification should reject an invalid signature"
    );
}

#[test]
fn test_verify_zebra_prehashed_rejects_noncanonical_s() {
    let signing_key = SigningKey::from([4u8; 32]);
    let verification_key = VerificationKey::from(&signing_key);
    let mut sig_bytes: [u8; 64] = signing_key.sign(b"noncanonical s").into();
    sig_bytes[32..].copy_from_slice(&constants::BASEPOINT_ORDER.to_bytes());
    let signature = Signature::from(sig_bytes);

    assert_eq!(
        verification_key.verify_zebra_prehashed(&signature, Scalar::from(1u64)),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn test_verify_zebra_prehashed_rejects_undecodable_r() {
    let signing_key = SigningKey::from([5u8; 32]);
    let verification_key = VerificationKey::from(&signing_key);
    let mut sig_bytes: [u8; 64] = signing_key.sign(b"undecodable r").into();
    let invalid_r = first_undecodable_r();
    assert!(CompressedEdwardsY(invalid_r).decompress().is_none());

    sig_bytes[..32].copy_from_slice(&invalid_r);
    let signature = Signature::from(sig_bytes);

    assert_eq!(
        verification_key.verify_zebra_prehashed(&signature, Scalar::from(1u64)),
        Err(Error::InvalidSignature)
    );
}

fn first_undecodable_r() -> [u8; 32] {
    for candidate in 0u16..=u16::MAX {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&candidate.to_le_bytes());
        if CompressedEdwardsY(bytes).decompress().is_none() {
            return bytes;
        }
    }

    panic!("failed to find an undecodable compressed Edwards-Y encoding");
}

#[cfg(feature = "std")]
#[test]
fn test_verify_dalek_matches_legacy_edge_cases() {
    for case in SMALL_ORDER_SIGS.iter() {
        let sig = Signature::from(case.sig_bytes);
        let vk = VerificationKey::try_from(case.vk_bytes).unwrap();
        let result = vk.verify_dalek(&sig, b"Zcash");

        assert_eq!(
            result.is_ok(),
            case.valid_legacy,
            "dalek-compatible verification mismatch for vk={} sig={}",
            hex::encode(case.vk_bytes),
            hex::encode(case.sig_bytes)
        );
    }
}
