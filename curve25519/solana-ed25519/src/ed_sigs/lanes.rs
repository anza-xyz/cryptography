// -*- mode: rust; -*-
//
// This file is part of solana-ed25519's ed_sigs module.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE-APACHE and LICENSE-MIT for licensing information.

//! Wide-lane batch verification with per-signature verdicts.
//!
//! Groups of eight verification equations advance in lockstep, one signature
//! per SIMD lane, and every signature gets its own accept or reject verdict.
//! Each lane checks the same HEEA-transformed cofactored equation, and with
//! the same ZIP-215 semantics, as [`VerificationKey::verify`].

#![allow(non_snake_case)]

use alloc::vec::Vec;

use sha2::{Sha512, digest::Update};

use crate::backend::lanes::GroupDigits;
use crate::backend::lanes::digits::{HEEA_DIGITS, joint_digits, negate, signed_digits};
use crate::backend::lanes::edwards_x8::{
    CompletedPointX8, ExtendedPointX8, LookupTableX8, ProjectivePointX8, decompress_x8,
    table_from_affine_lanes,
};
use crate::backend::lanes::field_x8::{LANES, LaneMask};
use crate::backend::lanes::joint::JOINT_TABLE_B;
use crate::backend::serial::curve_models::AffineNielsPoint;
use crate::constants::EDWARDS_D2;
use crate::edwards::CompressedEdwardsY;
use crate::field::FieldElement;
use crate::scalar::Scalar;
use crate::traits::HEEADecomposition;

use super::{Signature, VerificationKey, VerificationKeyBytes, scalar_from_sha512};

/// Verify a batch of `(key, signature, message)` triples, returning one
/// verdict per input in order.
///
/// Verdicts are independent: an invalid signature never affects another input.
/// A tail shorter than a full group falls back to the single-signature verifier.
pub fn verify_batch(items: &[(VerificationKeyBytes, Signature, &[u8])]) -> Vec<bool> {
    // Without the fused AVX-512 path the single-signature verifier beats the
    // portable lane fallback, so dispatch there instead.
    if !lane_engine_available() {
        return items
            .iter()
            .map(|(vk_bytes, sig, msg)| {
                VerificationKey::try_from(*vk_bytes)
                    .and_then(|vk| vk.verify(sig, msg))
                    .is_ok()
            })
            .collect();
    }

    verify_batch_force_lanes(items)
}

/// [`verify_batch`] on a named kernel, bypassing host dispatch.
#[doc(hidden)]
pub fn verify_batch_with(
    items: &[(VerificationKeyBytes, Signature, &[u8])],
    engine: Engine,
) -> Vec<bool> {
    verify_batch_lanes(items, engine)
}

/// Whether the wide-lane path beats the single-signature verifier here.
///
/// AArch64 is excluded even though the NEON kernels exist: a NEON multiply
/// needs as many widening multiplies per lane as a serial one.
#[inline]
fn lane_engine_available() -> bool {
    #[cfg(curve25519_backend = "simd")]
    {
        crate::backend::lanes::ifma_x8::available()
    }
    #[cfg(not(curve25519_backend = "simd"))]
    {
        false
    }
}

/// Which curve-stage kernel a group runs on.
///
/// Only AArch64 offers a choice of lane width, and only benchmarks and the
/// differential harness ask for anything but [`Engine::Default`].
#[doc(hidden)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Engine {
    /// The wired-in kernel for this host.
    Default,
    /// The lane-at-a-time fallback, on every architecture.
    Portable,
    /// NEON at the given lane width: 2, 4 or 8.
    Neon(usize),
}

/// Field-multiply throughput probe at one curve-stage kernel. Benches only.
#[doc(hidden)]
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub fn field_mul_probe(engine: Engine, rounds: usize) -> u32 {
    use crate::backend::lanes::neon::{Width, field_mul_probe};
    let width = match engine {
        Engine::Neon(2) => Some(Width::X2),
        Engine::Neon(4) => Some(Width::X4),
        Engine::Neon(8) => Some(Width::X8),
        _ => None,
    };
    field_mul_probe(width, rounds)
}

/// The lane pipeline unconditionally, portable fallback included, so tests
/// cover that path on every architecture.
pub(crate) fn verify_batch_force_lanes(
    items: &[(VerificationKeyBytes, Signature, &[u8])],
) -> Vec<bool> {
    verify_batch_lanes(items, Engine::Default)
}

/// Batch length up to which the group ordering needs no allocation.
const ORDER_STACK_CAP: usize = 128;

/// SHA-512 blocks one message costs, counting the `R || A` prefix and padding.
#[inline]
fn hash_blocks(msg_len: usize) -> u32 {
    (64 + msg_len + 1 + 16).div_ceil(128) as u32
}

/// Run `items` through the lane pipeline grouped by hash cost, returning
/// verdicts in the caller's order.
///
/// A group's lanes advance to the longest message's block count, so grouping by
/// cost keeps a long message from charging the short ones.
fn verify_ordered<T: Copy>(
    items: &[T],
    msg_of: impl Fn(&T) -> &[u8],
    group_of: impl Fn(&[T; LANES]) -> LaneMask,
    single_of: impl Fn(&T) -> bool,
) -> Vec<bool> {
    let n = items.len();
    let mut verdicts = alloc::vec![false; n];

    let mut stack = [0u32; ORDER_STACK_CAP];
    let mut heap: Vec<u32>;
    let order: &mut [u32] = if n <= ORDER_STACK_CAP {
        for (i, slot) in stack[..n].iter_mut().enumerate() {
            *slot = i as u32;
        }
        &mut stack[..n]
    } else {
        heap = (0..n as u32).collect();
        &mut heap[..]
    };
    // Index as tiebreak, so the unstable sort is stable in effect.
    order.sort_unstable_by_key(|&i| (hash_blocks(msg_of(&items[i as usize]).len()), i));

    let mut chunks = order.chunks_exact(LANES);
    for group in chunks.by_ref() {
        let lanes: [T; LANES] = core::array::from_fn(|l| items[group[l] as usize]);
        let group_verdicts = group_of(&lanes);
        for (l, &i) in group.iter().enumerate() {
            verdicts[i as usize] = group_verdicts[l];
        }
    }

    // Tails of four or more are cheaper padded into one group, with the pad
    // lanes repeating the first tail item; shorter tails verify singly.
    let tail = chunks.remainder();
    if tail.len() >= 4 {
        let lanes: [T; LANES] = core::array::from_fn(|l| items[tail[l % tail.len()] as usize]);
        let group_verdicts = group_of(&lanes);
        for (l, &i) in tail.iter().enumerate() {
            verdicts[i as usize] = group_verdicts[l];
        }
    } else {
        for &i in tail.iter() {
            verdicts[i as usize] = single_of(&items[i as usize]);
        }
    }

    verdicts
}

fn verify_batch_lanes(
    items: &[(VerificationKeyBytes, Signature, &[u8])],
    engine: Engine,
) -> Vec<bool> {
    verify_ordered(
        items,
        |item| item.2,
        |group| verify_group(group, engine),
        |(vk_bytes, sig, msg)| {
            VerificationKey::try_from(*vk_bytes)
                .and_then(|vk| vk.verify(sig, msg))
                .is_ok()
        },
    )
}

/// The scalar challenge hashes, one lane at a time.
fn challenge_scalars_serial(
    a_bytes: &[[u8; 32]; LANES],
    r_bytes: &[[u8; 32]; LANES],
    msgs: &[&[u8]; LANES],
) -> [Scalar; LANES] {
    core::array::from_fn(|l| {
        scalar_from_sha512(
            Sha512::default()
                .chain(&r_bytes[l][..])
                .chain(&a_bytes[l][..])
                .chain(msgs[l]),
        )
    })
}

/// Shared per-lane scalar preparation: challenge hashing, `s` canonicality,
/// HEEA decomposition and digit schedules.
fn prepare_group(
    a_bytes: &[[u8; 32]; LANES],
    r_bytes: &[[u8; 32]; LANES],
    s_bytes: &[[u8; 32]; LANES],
    msgs: &[&[u8]; LANES],
) -> (GroupDigits, LaneMask) {
    // Challenge scalars k = H(R || A || M) mod l, hashed eight-wide when the
    // vector unit is available.
    #[cfg(curve25519_backend = "simd")]
    let k: [Scalar; LANES] = if crate::backend::lanes::ifma_x8::available() {
        let digests = unsafe {
            crate::backend::lanes::sha512_x8::challenge_digests_x8(r_bytes, a_bytes, msgs)
        };
        core::array::from_fn(|l| Scalar::from_bytes_mod_order_wide(&digests[l]))
    } else {
        challenge_scalars_serial(a_bytes, r_bytes, msgs)
    };
    #[cfg(not(curve25519_backend = "simd"))]
    let k: [Scalar; LANES] = challenge_scalars_serial(a_bytes, r_bytes, msgs);

    // s must be canonical; a non-canonical s invalidates only its own lane.
    let mut alive: LaneMask = [true; LANES];
    let s: [Scalar; LANES] = core::array::from_fn(|l| {
        match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes[l])) {
            Some(s) => s,
            None => {
                alive[l] = false;
                Scalar::ZERO
            }
        }
    });

    // HEEA per lane: rho == tau*k (mod l) up to the reported sign, giving the
    // equation tau*s B + rho A' - tau R with A' = -A when rho == tau*k and A' = A
    // otherwise, the sign folded into the rho digits. Working mod l is sound
    // here: the [8] multiplication annihilates the l-multiple and the torsion.
    let mut b = [[0u64; LANES]; HEEA_DIGITS];
    let mut a = [[0i8; HEEA_DIGITS]; LANES];
    let mut r = [[0i8; HEEA_DIGITS]; LANES];

    for l in 0..LANES {
        let (rho, tau, flip_k) = k[l].heea_decompose();
        let ts = tau * s[l];
        for (i, &d) in joint_digits(ts.as_bytes()).iter().enumerate() {
            b[i][l] = d as u64;
        }
        a[l] = signed_digits(&rho);
        if !flip_k {
            negate(&mut a[l]);
        }
        r[l] = signed_digits(&tau);
        negate(&mut r[l]);
    }

    // First digit position with any contribution.
    let mut start = 0;
    for i in (0..HEEA_DIGITS).rev() {
        let any = (0..LANES).any(|l| b[i][l] != 0 || a[l][i] != 0 || r[l][i] != 0);
        if any {
            start = i;
            break;
        }
    }

    (GroupDigits { b, a, r, start }, alive)
}

/// Dispatch one prepared group to the fused or portable curve stage.
fn run_curve_stage(
    a_encodings: &[[u8; 32]; LANES],
    r_encodings: &[[u8; 32]; LANES],
    prepared_a: Option<&LookupTableX8>,
    digits: &GroupDigits,
    alive: &LaneMask,
    engine: Engine,
) -> LaneMask {
    if engine != Engine::Portable {
        #[cfg(curve25519_backend = "simd")]
        if crate::backend::lanes::ifma_x8::available() {
            return unsafe {
                crate::backend::lanes::ifma_x8::fused::verify_curve_x8(
                    a_encodings,
                    r_encodings,
                    prepared_a,
                    digits,
                    alive,
                )
            };
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            use crate::backend::lanes::neon::{DEFAULT_WIDTH, Width};
            let width = match engine {
                Engine::Neon(2) => Width::X2,
                Engine::Neon(4) => Width::X4,
                Engine::Neon(8) => Width::X8,
                _ => DEFAULT_WIDTH,
            };
            return crate::backend::lanes::neon::verify_curve_neon(
                a_encodings,
                r_encodings,
                prepared_a,
                digits,
                alive,
                width,
            );
        }
    }

    verify_curve_portable(a_encodings, r_encodings, prepared_a, digits, alive)
}

/// Verify one full group of eight signatures in lockstep.
fn verify_group(
    group: &[(VerificationKeyBytes, Signature, &[u8]); LANES],
    engine: Engine,
) -> LaneMask {
    let a_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| group[l].0.0);
    let r_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| *group[l].1.r_bytes());
    let s_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| *group[l].1.s_bytes());
    let msgs: [&[u8]; LANES] = core::array::from_fn(|l| group[l].2);

    let (digits, alive) = prepare_group(&a_bytes, &r_bytes, &s_bytes, &msgs);
    run_curve_stage(&a_bytes, &r_bytes, None, &digits, &alive, engine)
}

/// A verification key prepared for the wide-lane verifier.
///
/// Holds \\([A, 2A, \ldots, 8A]\\) as canonical affine cached points, so
/// [`verify_batch_prepared`] skips decompression and per-group table
/// construction. Construction validates the encoding as [`VerificationKey`]
/// does, accepting non-canonical encodings.
pub struct PreparedLaneKey {
    vk_bytes: VerificationKeyBytes,
    multiples: [AffineNielsPoint; 8],
}

impl PreparedLaneKey {
    /// Decompress and precompute; fails exactly when
    /// [`VerificationKey::try_from`] would.
    pub fn new(vk_bytes: VerificationKeyBytes) -> Result<Self, super::Error> {
        let A = CompressedEdwardsY(vk_bytes.0)
            .decompress()
            .ok_or(super::Error::MalformedPublicKey)?;

        // Consecutive multiples [A, 2A, ..., 8A] in extended coordinates.
        let mut points = [A; 8];
        for j in 1..8 {
            points[j] = points[j - 1] + A;
        }

        // One shared inversion; the canonical limbs are within every bound the
        // vector kernels assume.
        let mut z_invs: [FieldElement; 8] = core::array::from_fn(|j| points[j].Z);
        FieldElement::invert_batch_alloc(&mut z_invs);
        let canonical =
            |v: &FieldElement| -> FieldElement { FieldElement::from_bytes(&v.to_bytes()) };
        let multiples = core::array::from_fn(|j| {
            let x = &points[j].X * &z_invs[j];
            let y = &points[j].Y * &z_invs[j];
            AffineNielsPoint {
                y_plus_x: canonical(&(&y + &x)),
                y_minus_x: canonical(&(&y - &x)),
                xy2d: canonical(&(&(&x * &y) * &EDWARDS_D2)),
            }
        });

        Ok(PreparedLaneKey {
            vk_bytes,
            multiples,
        })
    }

    /// The encoded key this preparation was built from.
    pub fn verification_key_bytes(&self) -> VerificationKeyBytes {
        self.vk_bytes
    }
}

/// [`verify_batch`] with prepared keys: identical verdicts, with the `A`
/// decompression and table construction moved into [`PreparedLaneKey::new`].
pub fn verify_batch_prepared(items: &[(&PreparedLaneKey, Signature, &[u8])]) -> Vec<bool> {
    if !lane_engine_available() {
        return items
            .iter()
            .map(|(key, sig, msg)| {
                VerificationKey::try_from(key.vk_bytes)
                    .and_then(|vk| vk.verify(sig, msg))
                    .is_ok()
            })
            .collect();
    }

    verify_batch_prepared_force_lanes(items)
}

/// See [`verify_batch_force_lanes`].
pub(crate) fn verify_batch_prepared_force_lanes(
    items: &[(&PreparedLaneKey, Signature, &[u8])],
) -> Vec<bool> {
    verify_batch_prepared_lanes(items, Engine::Default)
}

/// [`verify_batch_prepared`] on a named kernel, bypassing host dispatch.
#[doc(hidden)]
pub fn verify_batch_prepared_with(
    items: &[(&PreparedLaneKey, Signature, &[u8])],
    engine: Engine,
) -> Vec<bool> {
    verify_batch_prepared_lanes(items, engine)
}

fn verify_batch_prepared_lanes(
    items: &[(&PreparedLaneKey, Signature, &[u8])],
    engine: Engine,
) -> Vec<bool> {
    verify_ordered(
        items,
        |item| item.2,
        |group| verify_group_prepared(group, engine),
        |(key, sig, msg)| {
            VerificationKey::try_from(key.vk_bytes)
                .and_then(|vk| vk.verify(sig, msg))
                .is_ok()
        },
    )
}

/// Verify one full group of eight prepared-key signatures in lockstep.
fn verify_group_prepared(
    group: &[(&PreparedLaneKey, Signature, &[u8]); LANES],
    engine: Engine,
) -> LaneMask {
    let a_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| group[l].0.vk_bytes.0);
    let r_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| *group[l].1.r_bytes());
    let s_bytes: [[u8; 32]; LANES] = core::array::from_fn(|l| *group[l].1.s_bytes());
    let msgs: [&[u8]; LANES] = core::array::from_fn(|l| group[l].2);

    let (digits, alive) = prepare_group(&a_bytes, &r_bytes, &s_bytes, &msgs);
    let table = table_from_affine_lanes(&core::array::from_fn(|l| &group[l].0.multiples));
    run_curve_stage(&a_bytes, &r_bytes, Some(&table), &digits, &alive, engine)
}

/// The portable curve stage: identical structure to the fused IFMA path.
fn verify_curve_portable(
    a_encodings: &[[u8; 32]; LANES],
    r_encodings: &[[u8; 32]; LANES],
    prepared_a: Option<&LookupTableX8>,
    digits: &GroupDigits,
    alive_in: &LaneMask,
) -> LaneMask {
    let mut alive = *alive_in;

    // Eight-wide decompression, non-canonical accepted; a prepared table carries
    // known-valid `A` multiples and skips the `A` half.
    let owned_a: LookupTableX8;
    let table_A: &LookupTableX8 = match prepared_a {
        Some(t) => t,
        None => {
            let (A, a_valid) = decompress_x8(a_encodings);
            for l in 0..LANES {
                alive[l] &= a_valid[l];
            }
            owned_a = LookupTableX8::from_extended(&A);
            &owned_a
        }
    };

    let (R, r_valid) = decompress_x8(r_encodings);
    for l in 0..LANES {
        alive[l] &= r_valid[l];
    }

    let table_R = LookupTableX8::from_extended(&R);

    let mut acc: Option<ProjectivePointX8> = None;
    let mut last: Option<CompletedPointX8> = None;
    for i in (0..=digits.start).rev() {
        let mut e = match acc {
            Some(p) => {
                let mut p = p;
                for _ in 0..3 {
                    p = p.double().as_projective();
                }
                p.double().as_extended()
            }
            None => ExtendedPointX8::IDENTITY,
        };

        e = e.add(&JOINT_TABLE_B.select(&digits.b[i])).as_extended();
        e = e
            .add(&table_A.select(&core::array::from_fn(|l| digits.a[l][i])))
            .as_extended();
        let completed = e.add(&table_R.select(&core::array::from_fn(|l| digits.r[l][i])));
        acc = Some(completed.as_projective());
        last = Some(completed);
    }

    // Three cofactor doublings, then the identity test.
    let checked = match last {
        Some(c) => c.as_extended().mul_by_pow_2(3),
        None => ExtendedPointX8::IDENTITY,
    };

    let is_identity = checked.is_identity_lanes();
    core::array::from_fn(|l| alive[l] && is_identity[l])
}
