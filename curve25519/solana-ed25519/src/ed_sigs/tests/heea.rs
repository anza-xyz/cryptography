use crate::ed_sigs::SigningKey;
use crate::ed_sigs::VerificationKey;

#[test]
fn test_verify_heea_invalid_signature() {
    let mut rng = rand::rng();
    let signing_key = SigningKey::new(&mut rng);
    let verification_key = VerificationKey::from(&signing_key);

    let msg = b"Original message";
    let signature = signing_key.sign(msg);

    // Try to verify with different message
    let wrong_msg = b"Different message";

    let result_standard = verification_key.verify(&signature, wrong_msg);
    let result_heea = verification_key.verify_heea(&signature, wrong_msg);

    // Both should fail
    assert!(
        result_standard.is_err(),
        "Standard verification should fail for wrong message"
    );
    assert!(
        result_heea.is_err(),
        "heea verification should fail for wrong message"
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

        let result_standard = verification_key.verify(&signature, msg.as_bytes());
        let result_heea = verification_key.verify_heea(&signature, msg.as_bytes());

        assert!(
            result_standard.is_ok(),
            "Standard verification should succeed for signature {}",
            i
        );
        assert!(
            result_heea.is_ok(),
            "heea verification should succeed for signature {}",
            i
        );
    }
}
