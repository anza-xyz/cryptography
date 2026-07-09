#![cfg(all(feature = "alloc", feature = "rand_core"))]

use crate::ed_sigs::*;
use crate::edwards::CompressedEdwardsY;
use alloc::vec::Vec;

#[test]
fn batch_verify() {
    let mut batch = batch::Verifier::new();
    for i in 0..32 {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let sk = SigningKey::from(seed);
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&msg[..]);
        batch.queue((pk_bytes, sig, msg));
    }
    assert!(batch.verify().is_ok());
}

#[test]
fn batch_verify_with_one_bad_sig() {
    let bad_index = 10;
    let mut batch = batch::Verifier::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let sk = SigningKey::from(seed);
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = if i != bad_index {
            sk.sign(&msg[..])
        } else {
            sk.sign(b"badmsg")
        };
        let item: batch::Item = (pk_bytes, sig, msg).into();
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify().is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}

#[test]
fn batch_verify_with_malformed_verification_key() {
    let seed = [1u8; 32];
    let sk = SigningKey::from(seed);
    let msg = b"BatchVerifyTest";
    let sig = sk.sign(&msg[..]);
    let malformed_key = VerificationKeyBytes::from(first_undecodable_compressed_edwards_y());

    assert_eq!(
        VerificationKey::try_from(malformed_key),
        Err(Error::MalformedPublicKey)
    );

    let mut batch = batch::Verifier::new();
    batch.queue((malformed_key, sig, msg));

    assert_eq!(batch.verify(), Err(Error::MalformedPublicKey));
}

fn first_undecodable_compressed_edwards_y() -> [u8; 32] {
    for candidate in 0u16..=u16::MAX {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&candidate.to_le_bytes());
        if CompressedEdwardsY(bytes).decompress().is_none() {
            return bytes;
        }
    }

    panic!("failed to find an undecodable compressed Edwards-Y encoding");
}
