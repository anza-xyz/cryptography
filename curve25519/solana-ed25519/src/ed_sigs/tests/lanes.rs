#![cfg(feature = "alloc")]

use alloc::vec::Vec;

use crate::ed_sigs::{Signature, SigningKey, VerificationKey, VerificationKeyBytes, lanes};

/// The single-signature verifier's verdict, the oracle for every assertion.
fn single_verdict(vk_bytes: VerificationKeyBytes, sig: &Signature, msg: &[u8]) -> bool {
    VerificationKey::try_from(vk_bytes)
        .and_then(|vk| vk.verify(sig, msg))
        .is_ok()
}

fn assert_matches_single(items: &[(VerificationKeyBytes, Signature, &[u8])]) {
    let lane_verdicts = lanes::verify_batch_force_lanes(items);
    assert_eq!(lane_verdicts.len(), items.len());
    for (i, ((vk_bytes, sig, msg), lane_verdict)) in
        items.iter().zip(lane_verdicts.iter()).enumerate()
    {
        assert_eq!(
            *lane_verdict,
            single_verdict(*vk_bytes, sig, msg),
            "verdict mismatch at index {i}"
        );
    }
}

// honest signatures verify across every group and tail size
#[test]
fn honest_signatures_all_sizes() {
    let messages: Vec<Vec<u8>> = (0..21u8)
        .map(|i| alloc::vec![i ^ 0x5A; 3 + 11 * i as usize])
        .collect();
    let signed: Vec<(VerificationKeyBytes, Signature, &[u8])> = messages
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            let sk = SigningKey::from([i as u8 + 1; 32]);
            (
                VerificationKeyBytes::from(&sk),
                sk.sign(msg),
                msg.as_slice(),
            )
        })
        .collect();

    // 21 = 2 full groups + tail of 5.
    let verdicts = lanes::verify_batch_force_lanes(&signed);
    assert!(verdicts.iter().all(|&ok| ok), "honest signature rejected");
    assert_matches_single(&signed);

    // Sub-group sizes: single tails, padded tails and exact groups.
    for n in [0, 1, 3, 4, 7, 8, 9, 11, 12, 15, 16, 20] {
        assert_matches_single(&signed[..n]);
    }
}

/// Message lengths straddling every SHA-512 padding boundary, plus the sizes
/// the grouping sorts on.
const RAGGED_LENS: [usize; 11] = [0, 1, 63, 64, 65, 127, 128, 129, 200, 1232, 4096];

/// A deterministic LCG, so a ragged arrival order replays without an RNG.
fn lcg(state: &mut u32) -> usize {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    (*state >> 8) as usize
}

fn sign_all(messages: &[Vec<u8>]) -> Vec<(VerificationKeyBytes, Signature, &[u8])> {
    messages
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            let sk = SigningKey::from([i as u8 ^ 0xC3; 32]);
            (
                VerificationKeyBytes::from(&sk),
                sk.sign(msg),
                msg.as_slice(),
            )
        })
        .collect()
}

// group ordering does not change a verdict, whatever order the lengths arrive in
#[test]
fn ragged_lengths_match_single() {
    let mut rng = 0x1234_5678u32;

    for round in 0..8usize {
        // 4 through 25: serial tails, padded tails and multiple full groups.
        let n = 4 + round * 3;
        let messages: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let len = if round % 2 == 0 {
                    RAGGED_LENS[lcg(&mut rng) % RAGGED_LENS.len()]
                } else {
                    lcg(&mut rng) % 4200
                };
                alloc::vec![(i as u8) ^ 0x3C; len]
            })
            .collect();

        let signed = sign_all(&messages);
        let verdicts = lanes::verify_batch_force_lanes(&signed);
        assert!(
            verdicts.iter().all(|&ok| ok),
            "honest ragged signature rejected in round {round}"
        );
        assert_matches_single(&signed);
    }
}

// every verdict returns to the input it belongs to, at anti-sorted lengths
#[test]
fn mixed_validity_survives_length_grouping() {
    let lens = [
        4096usize, 0, 1232, 1, 200, 63, 129, 64, 128, 65, 127, 1232, 0, 4096, 200,
    ];
    let messages: Vec<Vec<u8>> = lens
        .iter()
        .enumerate()
        .map(|(i, &n)| alloc::vec![(i as u8) ^ 0x9E; n])
        .collect();

    let mut items = sign_all(&messages);

    // Every third item is broken, in a different way each time.
    for (i, item) in items.iter_mut().enumerate() {
        match i % 3 {
            1 => {
                let mut bad: [u8; 64] = item.1.into();
                bad[i % 64] ^= 0x08;
                item.1 = Signature::from(bad);
            }
            2 => {
                let mut bad: [u8; 64] = item.1.into();
                bad[32..].copy_from_slice(&[0xff; 32]);
                bad[63] &= 0x1f;
                item.1 = Signature::from(bad);
            }
            _ => {}
        }
    }

    let verdicts = lanes::verify_batch_force_lanes(&items);
    assert!(
        verdicts.iter().any(|&ok| ok) && verdicts.iter().any(|&ok| !ok),
        "test needs both verdicts present to detect a permutation bug"
    );
    for (i, &ok) in verdicts.iter().enumerate() {
        assert_eq!(ok, i % 3 == 0, "verdict landed on the wrong input at {i}");
    }
    assert_matches_single(&items);
}

// batches either side of the point where the group ordering leaves the stack
#[test]
fn ordering_spans_the_stack_limit() {
    let mut rng = 0xFEED_0BADu32;

    for n in [127usize, 128, 129, 200] {
        let messages: Vec<Vec<u8>> = (0..n)
            .map(|i| alloc::vec![i as u8; lcg(&mut rng) % 400])
            .collect();
        let mut items = sign_all(&messages);

        // Break a few, at indices the ordering will scatter.
        for i in (3..n).step_by(17) {
            let mut bad: [u8; 64] = items[i].1.into();
            bad[i % 64] ^= 0x20;
            items[i].1 = Signature::from(bad);
        }

        let verdicts = lanes::verify_batch_force_lanes(&items);
        for (i, &ok) in verdicts.iter().enumerate() {
            assert_eq!(ok, !(i >= 3 && (i - 3) % 17 == 0), "n={n}, index {i}");
        }
        assert_matches_single(&items);
    }
}

// an invalid input of any kind rejects its own lane and no other
#[test]
fn invalid_lanes_are_independent() {
    let msg: &[u8] = b"wide lanes";
    let mut items: Vec<(VerificationKeyBytes, Signature, &[u8])> = (0..8u8)
        .map(|i| {
            let sk = SigningKey::from([40 + i; 32]);
            (VerificationKeyBytes::from(&sk), sk.sign(msg), msg)
        })
        .collect();

    // Lane 1: corrupted signature R bytes.
    let mut bad_sig: [u8; 64] = items[1].1.into();
    bad_sig[0] ^= 0x40;
    items[1].1 = Signature::from(bad_sig);

    // Lane 2: non-canonical (>= l) scalar s.
    let mut bad_s: [u8; 64] = items[2].1.into();
    bad_s[32..].copy_from_slice(&[0xff; 32]);
    bad_s[63] &= 0x1f; // keep the high bits plausible while exceeding l
    items[2].1 = Signature::from(bad_s);

    // Lane 3: public key bytes that do not decompress.
    items[3].0 = VerificationKeyBytes::from([0x05; 32]);

    // Lane 4: wrong message binding (signature from another key).
    let other = SigningKey::from([99; 32]);
    items[4].1 = other.sign(msg);

    let verdicts = lanes::verify_batch_force_lanes(&items);
    assert!(verdicts[0], "honest lane 0");
    assert!(!verdicts[1], "corrupted R");
    assert!(!verdicts[2], "non-canonical s");
    assert!(!verdicts[3], "invalid public key");
    assert!(!verdicts[4], "wrong key");
    assert!(
        verdicts[5] && verdicts[6] && verdicts[7],
        "healthy lanes unaffected"
    );

    assert_matches_single(&items);
}

// prepared-key verification returns the same verdicts as the byte-key path
#[test]
fn prepared_lane_keys_match_regular() {
    use crate::ed_sigs::lanes::PreparedLaneKey;

    let messages: Vec<Vec<u8>> = (0..13u8)
        .map(|i| alloc::vec![i; 5 + 7 * i as usize])
        .collect();
    let mut items: Vec<(VerificationKeyBytes, Signature, &[u8])> = messages
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            let sk = SigningKey::from([60 + i as u8; 32]);
            (
                VerificationKeyBytes::from(&sk),
                sk.sign(msg),
                msg.as_slice(),
            )
        })
        .collect();

    // Tamper: bad signature, wrong signer, non-canonical s.
    let mut bad: [u8; 64] = items[2].1.into();
    bad[5] ^= 0x11;
    items[2].1 = Signature::from(bad);
    items[6].1 = SigningKey::from([250; 32]).sign(b"other");
    let mut bad_s: [u8; 64] = items[9].1.into();
    bad_s[32..].copy_from_slice(&[0xee; 32]);
    items[9].1 = Signature::from(bad_s);

    let keys: Vec<PreparedLaneKey> = items
        .iter()
        .map(|(vk_bytes, _, _)| PreparedLaneKey::new(*vk_bytes).expect("valid key"))
        .collect();

    // 13 = 1 group + padded tail of 5.
    for n in [0, 2, 5, 8, 13] {
        let prepared_items: Vec<(&PreparedLaneKey, Signature, &[u8])> = items[..n]
            .iter()
            .enumerate()
            .map(|(i, (_, sig, msg))| (&keys[i], *sig, *msg))
            .collect();
        assert_eq!(
            lanes::verify_batch_prepared_force_lanes(&prepared_items),
            lanes::verify_batch_force_lanes(&items[..n]),
            "prepared/regular divergence at n={n}"
        );
    }

    // Construction fails exactly where decompression fails.
    assert!(PreparedLaneKey::new(VerificationKeyBytes::from([0x05; 32])).is_err());
}

// prepared keys from small-order and non-canonical encodings match the byte-key path
#[cfg(feature = "std")]
#[test]
fn prepared_small_order_keys_match_regular() {
    use crate::ed_sigs::lanes::PreparedLaneKey;

    let msg: &[u8] = b"Zcash";
    let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = super::small_order::SMALL_ORDER_SIGS
        .iter()
        .filter_map(|case| {
            let vkb = VerificationKeyBytes::from(case.vk_bytes);
            PreparedLaneKey::new(vkb)
                .ok()
                .map(|_| (vkb, Signature::from(case.sig_bytes), msg))
        })
        .collect();
    let keys: Vec<PreparedLaneKey> = items
        .iter()
        .map(|(vkb, _, _)| PreparedLaneKey::new(*vkb).expect("filtered valid"))
        .collect();
    let prepared_items: Vec<(&PreparedLaneKey, Signature, &[u8])> = items
        .iter()
        .enumerate()
        .map(|(i, (_, sig, msg))| (&keys[i], *sig, *msg))
        .collect();

    assert_eq!(
        lanes::verify_batch_prepared_force_lanes(&prepared_items),
        lanes::verify_batch_force_lanes(&items),
        "prepared/regular divergence on small-order cases"
    );
}

// lane verdicts match the single verifier on every ZIP-215 small-order case
#[cfg(feature = "std")]
#[test]
fn small_order_cases_match_single_verify() {
    let msg: &[u8] = b"Zcash";
    let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = super::small_order::SMALL_ORDER_SIGS
        .iter()
        .map(|case| {
            (
                VerificationKeyBytes::from(case.vk_bytes),
                Signature::from(case.sig_bytes),
                msg,
            )
        })
        .collect();

    assert_matches_single(&items);
}

// the public entry points agree with the forced lane pipeline on any host
#[test]
fn public_dispatch_matches_forced() {
    let msg: &[u8] = b"dispatch";
    let items: Vec<(VerificationKeyBytes, Signature, &[u8])> = (0..9u8)
        .map(|i| {
            let sk = SigningKey::from([70 + i; 32]);
            (VerificationKeyBytes::from(&sk), sk.sign(msg), msg)
        })
        .collect();
    assert_eq!(
        lanes::verify_batch(&items),
        lanes::verify_batch_force_lanes(&items)
    );
}
