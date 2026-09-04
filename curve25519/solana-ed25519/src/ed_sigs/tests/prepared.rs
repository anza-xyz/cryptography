#![cfg(feature = "alloc")]

use sha2::{Sha512, digest::Update};

use crate::ed_sigs::{PreparedVerificationKey, SigningKey, VerificationKey, scalar_from_sha512};
use crate::traits::HEEADecomposition;

// prepared verification agrees with `verify` on both signs of the decomposition
#[test]
fn prepared_matches_verify_zebra() {
    let mut flips_seen = [false; 2];

    for seed in 0u8..64 {
        let sk = SigningKey::from([seed; 32]);
        let vk = VerificationKey::from(&sk);
        let prepared = PreparedVerificationKey::from(&vk);

        let msg = [seed ^ 0xA5; 40];
        let sig = sk.sign(&msg);

        // Record which sign of the decomposition this signature takes.
        let h = scalar_from_sha512(
            Sha512::default()
                .chain(&sig.r_bytes()[..])
                .chain(vk.as_ref())
                .chain(msg),
        );
        let (_, _, flip_h) = h.heea_decompose();
        flips_seen[flip_h as usize] = true;

        assert_eq!(vk.verify(&sig, &msg), Ok(()));
        assert_eq!(prepared.verify(&sig, &msg), Ok(()));

        let mut bad_msg = msg;
        bad_msg[0] ^= 1;
        assert!(vk.verify(&sig, &bad_msg).is_err());
        assert!(prepared.verify(&sig, &bad_msg).is_err());
    }

    assert!(
        flips_seen[0] && flips_seen[1],
        "test vectors did not cover both HEEA signs"
    );
}

// prepared verification matches `verify` on the ZIP-215 small-order cases
#[cfg(feature = "std")]
#[test]
fn prepared_matches_verify_on_small_order_cases() {
    use ed25519::Signature;

    for case in super::small_order::SMALL_ORDER_SIGS.iter() {
        let msg = b"Zcash";
        let sig = Signature::from(case.sig_bytes);
        let Ok(vk) = VerificationKey::try_from(case.vk_bytes) else {
            continue;
        };
        let prepared = vk.prepare();
        assert_eq!(
            vk.verify(&sig, msg).is_ok(),
            prepared.verify(&sig, msg).is_ok(),
            "prepared/regular verify disagree on {case:?}"
        );
    }
}
