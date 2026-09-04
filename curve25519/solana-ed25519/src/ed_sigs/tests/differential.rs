//! Randomised differential harness: the wide-lane verifier against the
//! single-signature verifier, lane for lane.
//!
//! Batches are drawn from a seeded RNG, mixing honest signatures with corrupted
//! scalars, corrupted points, wrong keys, non-canonical encodings and the
//! 8-torsion, at every batch length that reaches a different tail path. The
//! asserted property is exact agreement with the single verifier, not that both
//! reject. `ED25519_DIFF_ROUNDS` sets the round count; a failure prints the
//! seed that replays just that round.

#![cfg(all(feature = "alloc", feature = "std"))]

use alloc::vec::Vec;

use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::util;
use crate::{
    constants::EIGHT_TORSION,
    ed_sigs::{Signature, SigningKey, VerificationKey, VerificationKeyBytes, lanes},
};

/// What the single-signature verifier says, the oracle for every assertion.
fn single_verdict(vk_bytes: VerificationKeyBytes, sig: &Signature, msg: &[u8]) -> bool {
    VerificationKey::try_from(vk_bytes)
        .and_then(|vk| vk.verify(sig, msg))
        .is_ok()
}

/// How an item was built, so a failure names the shape that broke it.
#[derive(Clone, Copy, Debug)]
enum Shape {
    Honest,
    CorruptS,
    CorruptR,
    CorruptMsg,
    WrongKey,
    NonCanonicalS,
    NonCanonicalA,
    NonCanonicalR,
    SmallOrderA,
    SmallOrderR,
}

const SHAPES: [Shape; 12] = [
    Shape::Honest,
    Shape::Honest,
    Shape::Honest,
    Shape::CorruptS,
    Shape::CorruptR,
    Shape::CorruptMsg,
    Shape::WrongKey,
    Shape::NonCanonicalS,
    Shape::NonCanonicalA,
    Shape::NonCanonicalR,
    Shape::SmallOrderA,
    Shape::SmallOrderR,
];

struct Item {
    vk: VerificationKeyBytes,
    sig: Signature,
    msg: Vec<u8>,
    shape: Shape,
}

fn torsion_encodings() -> Vec<[u8; 32]> {
    EIGHT_TORSION
        .iter()
        .map(|p| p.compress().to_bytes())
        .collect()
}

/// One item of a randomly chosen shape.
fn make_item(rng: &mut StdRng, shape: Shape) -> Item {
    // The lengths where the x8 hash's staging changes: the prefix block, the
    // marker block and the length block all separate there.
    const BOUNDARY_LENS: [usize; 11] = [0, 1, 47, 48, 63, 64, 65, 111, 127, 128, 129];
    let len = match rng.random_range(0..6) {
        0 => 0,
        1 => rng.random_range(1..128),
        2 => rng.random_range(128..1232),
        3 => 1232,
        4 => BOUNDARY_LENS[rng.random_range(0..BOUNDARY_LENS.len())],
        _ => rng.random_range(1232..4200),
    };
    let msg: Vec<u8> = (0..len).map(|_| rng.random()).collect();

    let sk = SigningKey::from(rng.random::<[u8; 32]>());
    let vk = VerificationKeyBytes::from(&sk);
    let sig = sk.sign(&msg);

    let mut sig_bytes: [u8; 64] = sig.into();
    let mut vk_bytes: [u8; 32] = vk.into();
    let mut msg = msg;

    match shape {
        Shape::Honest => {}
        Shape::CorruptS => {
            let i = rng.random_range(32..64);
            sig_bytes[i] ^= 1 << rng.random_range(0..8);
        }
        Shape::CorruptR => {
            let i = rng.random_range(0..32);
            sig_bytes[i] ^= 1 << rng.random_range(0..8);
        }
        Shape::CorruptMsg => {
            if msg.is_empty() {
                msg.push(rng.random());
            } else {
                let i = rng.random_range(0..msg.len());
                msg[i] ^= 1 << rng.random_range(0..8);
            }
        }
        Shape::WrongKey => {
            let other = SigningKey::from(rng.random::<[u8; 32]>());
            vk_bytes = VerificationKeyBytes::from(&other).into();
        }
        Shape::NonCanonicalS => {
            // s >= l must be rejected, and a canonical-looking high s is the
            // interesting near-miss.
            let enc = util::non_canonical_field_encodings();
            sig_bytes[32..].copy_from_slice(&enc[rng.random_range(0..enc.len())]);
        }
        Shape::NonCanonicalA => {
            let enc = util::non_canonical_point_encodings();
            vk_bytes = enc[rng.random_range(0..enc.len())];
        }
        Shape::NonCanonicalR => {
            let enc = util::non_canonical_point_encodings();
            sig_bytes[..32].copy_from_slice(&enc[rng.random_range(0..enc.len())]);
        }
        Shape::SmallOrderA => {
            let t = torsion_encodings();
            vk_bytes = t[rng.random_range(0..t.len())];
        }
        Shape::SmallOrderR => {
            let t = torsion_encodings();
            sig_bytes[..32].copy_from_slice(&t[rng.random_range(0..t.len())]);
        }
    }

    Item {
        vk: VerificationKeyBytes::from(vk_bytes),
        sig: Signature::from(sig_bytes),
        msg,
        shape,
    }
}

/// Batch lengths reaching a different path: singles, serial tails, padded
/// tails, exact groups and multiple groups.
const LENGTHS: [usize; 14] = [1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 24, 33];

const DEFAULT_ROUNDS: usize = 2_000;

fn rounds() -> usize {
    std::env::var("ED25519_DIFF_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ROUNDS)
}

// every lane verdict equals the single verifier's, over randomised batches
#[test]
fn lanes_match_single_verifier() {
    let total = rounds();

    for round in 0..total {
        // Seeded per round, so a failure replays from this round's seed alone.
        let mut rng = StdRng::seed_from_u64(round as u64);
        let n = LENGTHS[round % LENGTHS.len()];

        let items: Vec<Item> = (0..n)
            .map(|_| {
                let shape = SHAPES[rng.random_range(0..SHAPES.len())];
                make_item(&mut rng, shape)
            })
            .collect();

        let batch: Vec<(VerificationKeyBytes, Signature, &[u8])> = items
            .iter()
            .map(|it| (it.vk, it.sig, it.msg.as_slice()))
            .collect();

        // The forced-lane path, the public dispatch (which may legitimately
        // choose the serial verifier) and every kernel this host offers. The
        // portable fallback runs one round in eight, since it paces the run.
        let mut runs: Vec<(&str, Vec<bool>)> = alloc::vec![
            ("force_lanes", lanes::verify_batch_force_lanes(&batch)),
            ("dispatch", lanes::verify_batch(&batch)),
        ];
        if round % 8 == 0 {
            runs.push((
                "portable",
                lanes::verify_batch_with(&batch, lanes::Engine::Portable),
            ));
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        for width in [2usize, 4, 8] {
            let label = match width {
                2 => "neon x2",
                4 => "neon x4",
                _ => "neon x8",
            };
            runs.push((
                label,
                lanes::verify_batch_with(&batch, lanes::Engine::Neon(width)),
            ));
        }

        for (label, verdicts) in runs {
            assert_eq!(verdicts.len(), n, "{label}: wrong verdict count");
            for (i, (it, got)) in items.iter().zip(verdicts.iter()).enumerate() {
                let want = single_verdict(it.vk, &it.sig, it.msg.as_slice());
                if *got != want {
                    panic!(
                        "{label}: verdict mismatch\n  \
                         round {round} (ED25519_DIFF_ROUNDS seed), batch len {n}, lane {i}\n  \
                         shape {:?}, msg len {}\n  \
                         lane said {got}, single verifier said {want}",
                        it.shape,
                        it.msg.len(),
                    );
                }
            }
        }
    }
}

// the same property for the prepared-key verifier, which reaches `A` differently
#[test]
fn prepared_lanes_match_single_verifier() {
    let total = rounds();

    for round in 0..total {
        let mut rng = StdRng::seed_from_u64(0x5eed_0000 ^ round as u64);
        let n = LENGTHS[round % LENGTHS.len()];

        let items: Vec<Item> = (0..n)
            .map(|_| {
                let shape = SHAPES[rng.random_range(0..SHAPES.len())];
                make_item(&mut rng, shape)
            })
            .collect();

        // A key that will not decompress must be rejected up front.
        let prepared: Vec<Option<lanes::PreparedLaneKey>> = items
            .iter()
            .map(|it| lanes::PreparedLaneKey::new(it.vk).ok())
            .collect();

        for (it, key) in items.iter().zip(prepared.iter()) {
            let want_decompressible = VerificationKey::try_from(it.vk).is_ok();
            assert_eq!(
                key.is_some(),
                want_decompressible,
                "round {round}: PreparedLaneKey::new disagrees with \
                 VerificationKey::try_from on shape {:?}",
                it.shape
            );
        }

        // Verify the subset whose keys prepared, against the same oracle.
        let usable: Vec<(&lanes::PreparedLaneKey, Signature, &[u8])> = items
            .iter()
            .zip(prepared.iter())
            .filter_map(|(it, key)| key.as_ref().map(|k| (k, it.sig, it.msg.as_slice())))
            .collect();
        if usable.is_empty() {
            continue;
        }

        let verdicts = lanes::verify_batch_prepared(&usable);
        assert_eq!(verdicts.len(), usable.len());
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        for width in [2usize, 4, 8] {
            assert_eq!(
                lanes::verify_batch_prepared_with(&usable, lanes::Engine::Neon(width)),
                verdicts,
                "prepared neon x{width} disagrees with dispatch, round {round}"
            );
        }

        let originals: Vec<&Item> = items
            .iter()
            .zip(prepared.iter())
            .filter_map(|(it, key)| key.as_ref().map(|_| it))
            .collect();
        for (i, (it, got)) in originals.iter().zip(verdicts.iter()).enumerate() {
            let want = single_verdict(it.vk, &it.sig, it.msg.as_slice());
            assert_eq!(
                *got, want,
                "prepared: verdict mismatch\n  round {round}, lane {i}, \
                 shape {:?}, msg len {}",
                it.shape,
                it.msg.len()
            );
        }
    }
}

// every small-order key and R encoding, paired exhaustively, through the lanes
#[test]
fn torsion_pairs_match_single_verifier() {
    let encodings: Vec<[u8; 32]> = torsion_encodings()
        .into_iter()
        .chain(util::non_canonical_point_encodings().into_iter().take(6))
        .collect();

    let msg: &[u8] = b"torsion";
    let mut items: Vec<Item> = Vec::new();
    for a in &encodings {
        for r in &encodings {
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(r);
            // s = 0 is canonical, so the verdict turns purely on the points.
            items.push(Item {
                vk: VerificationKeyBytes::from(*a),
                sig: Signature::from(sig_bytes),
                msg: msg.to_vec(),
                shape: Shape::SmallOrderR,
            });
        }
    }

    // Chunked at sizes that hit both the padded tail and full groups.
    for chunk in [8usize, 13, 16] {
        for group in items.chunks(chunk) {
            let batch: Vec<(VerificationKeyBytes, Signature, &[u8])> = group
                .iter()
                .map(|it| (it.vk, it.sig, it.msg.as_slice()))
                .collect();
            let verdicts = lanes::verify_batch_force_lanes(&batch);
            for (i, (it, got)) in group.iter().zip(verdicts.iter()).enumerate() {
                assert_eq!(
                    *got,
                    single_verdict(it.vk, &it.sig, it.msg.as_slice()),
                    "torsion pair mismatch at chunk {chunk} lane {i}"
                );
            }
        }
    }
}
