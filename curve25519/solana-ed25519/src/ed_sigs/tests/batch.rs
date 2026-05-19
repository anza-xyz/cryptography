#![cfg(all(feature = "alloc", feature = "rand_core"))]

use crate::ed_sigs::*;
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
    assert!(batch.verify(rand::thread_rng()).is_ok());
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
    assert!(batch.verify(rand::thread_rng()).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}
