use crate::ed_sigs::SigningKey;
use crate::ed_sigs::VerificationKey;
#[cfg(feature = "std")]
use crate::ed_sigs::tests::small_order::SMALL_ORDER_SIGS;
#[cfg(feature = "std")]
use core::convert::TryFrom;
#[cfg(feature = "std")]
use ed25519::Signature;

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
