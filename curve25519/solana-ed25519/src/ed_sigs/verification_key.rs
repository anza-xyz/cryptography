// -*- mode: rust; -*-
//
// This file is part of solana-ed25519's ed_sigs module, forked from ed25519-zebra.
// Original ed25519-zebra code: Copyright (c) Zcash Foundation contributors
// Modifications for HEEA: Copyright (c) 2025 curve25519-sol contributors
// See LICENSE-APACHE and LICENSE-MIT for licensing information.
//
// Modifications from ed25519-zebra:
// - Added `verify_zebra`, an accelerated verification path using the HEEA
//   scalar decomposition from curve25519-sol's `HEEADecomposition` trait.
//   See "Accelerating EdDSA Signature Verification with Faster Scalar Size
//   Halving" (TCHES 2025) for the algorithm.
// - `verify` dispatches to `verify_zebra`, preserving ZIP-215 semantics.

use crate::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{HEEADecomposition, IsIdentity},
};
use core::convert::{TryFrom, TryInto};
use sha2::{Sha512, digest::Update};
#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

use ed25519::{Signature, signature::Verifier};

#[cfg(feature = "pkcs8")]
use pkcs8::der::asn1::BitStringRef;
#[cfg(feature = "pkcs8")]
use pkcs8::spki::{
    AlgorithmIdentifierRef, DecodePublicKey, EncodePublicKey, Error as SpkiError,
    SubjectPublicKeyInfoRef,
};
#[cfg(feature = "pkcs8")]
use pkcs8::{Document, ObjectIdentifier};

use super::{Error, scalar_from_sha512};

/// The length of an ed25519 `VerificationKey`, in bytes.
pub const VERIFICATION_KEY_LENGTH: usize = 32;

#[cfg(feature = "pkcs8")]
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112"); // RFC 8410
#[cfg(feature = "pkcs8")]
const ALGORITHM_ID: AlgorithmIdentifierRef<'_> = AlgorithmIdentifierRef {
    oid: OID,
    parameters: None,
};

/// solana-ed25519's legacy `R` blacklist, kept byte-for-byte for Dalek policy
/// compatibility.
pub(crate) const LEGACY_EXCLUDED_R_ENCODINGS: [[u8; 32]; 11] = [
    // Canonical encoding of a y=0 order-4 point.
    [0x00; 32],
    // Canonical identity encoding: y=1, x=0.
    {
        let mut e = [0x00; 32];
        e[0] = 0x01;
        e
    },
    // Canonical encoding of an order-8 point.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // Canonical encoding of an order-8 point.
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // Valid canonical encoding of a non-small-order point included by the legacy blacklist.
    [
        0x13, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    // Invalid encoding; it does not decompress to an Edwards point.
    [
        0xb4, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
    // Canonical encoding of the order-2 point: y=-1, x=0.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Non-canonical y=p encoding of the same y=0 order-4 point as entry 0.
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Non-canonical y=p+1 encoding of the identity point.
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Invalid encoding; y=p-20 with the x sign bit set is not on the curve.
    [
        0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    // Valid canonical encoding of a non-small-order point included by the legacy blacklist.
    [
        0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
];

pub(crate) fn r_encoding_is_legacy_excluded(r_bytes: &[u8; 32]) -> bool {
    LEGACY_EXCLUDED_R_ENCODINGS.contains(r_bytes)
}

/// A container for the 32-byte encoded form of an Ed25519 verification key.
///
/// This type only checks or carries the byte length. It does not prove that the
/// bytes decompress to a valid Ed25519 verification key. Convert it to
/// [`VerificationKey`] to validate the encoded point and cache decoded state
/// used in signature verification.
///
/// A `VerificationKeyBytes` can be used to verify a single signature using the
/// following idiom:
/// ```
/// use core::convert::TryFrom;
/// # use curve25519::ed_sigs::*;
/// # let msg = b"Zcash";
/// # let sk = SigningKey::from_bytes(&[1u8; 32]);
/// # let sig = sk.sign(msg);
/// # let vk_bytes = VerificationKeyBytes::from(&sk);
/// VerificationKey::try_from(vk_bytes)
///     .and_then(|vk| vk.verify(&sig, msg));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes(pub(crate) [u8; VERIFICATION_KEY_LENGTH]);

impl core::fmt::Debug for VerificationKeyBytes {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_tuple("VerificationKeyBytes")
            .field(&self.0)
            .finish()
    }
}

impl AsRef<[u8]> for VerificationKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl TryFrom<&[u8]> for VerificationKeyBytes {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKeyBytes, Self::Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes {
        VerificationKeyBytes(bytes)
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(refined: VerificationKeyBytes) -> [u8; 32] {
        refined.0
    }
}

#[cfg(feature = "pkcs8")]
impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for VerificationKeyBytes {
    type Error = Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'a>) -> Result<VerificationKeyBytes, Error> {
        verification_key_bytes_from_spki(spki).map_err(|_| Error::MalformedPublicKey)
    }
}

#[cfg(feature = "pkcs8")]
fn verification_key_bytes_from_spki(
    spki: SubjectPublicKeyInfoRef<'_>,
) -> Result<VerificationKeyBytes, SpkiError> {
    if spki.algorithm.oid != OID {
        return Err(SpkiError::OidUnknown {
            oid: spki.algorithm.oid,
        });
    }

    if spki.algorithm != ALGORITHM_ID {
        return Err(SpkiError::KeyMalformed);
    }

    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(SpkiError::KeyMalformed)?;

    VerificationKeyBytes::try_from(bytes).map_err(|_| SpkiError::KeyMalformed)
}

/// A valid Ed25519 verification key.
///
/// This is also called a public key by other implementations.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which stores only the length-checked encoded bytes.
///
/// ## Zcash-specific consensus properties
///
/// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
/// [ZIP 215].  The verification criteria for an (encoded) verification key `A_bytes` are:
///
/// * `A_bytes` MUST be an encoding of a point `A` on the twisted Edwards form of
///   Curve25519, and non-canonical encodings MUST be accepted;
///
/// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes"))]
#[allow(non_snake_case)]
pub struct VerificationKey {
    pub(crate) A_bytes: VerificationKeyBytes,
    pub(crate) minus_A: EdwardsPoint,
}

impl From<VerificationKey> for VerificationKeyBytes {
    fn from(vk: VerificationKey) -> VerificationKeyBytes {
        vk.A_bytes
    }
}

impl AsRef<[u8]> for VerificationKey {
    fn as_ref(&self) -> &[u8] {
        &self.A_bytes.0[..]
    }
}

impl Default for VerificationKey {
    fn default() -> VerificationKey {
        let identity: EdwardsPoint = Default::default();
        let identity_bytes = identity.compress().to_bytes();

        VerificationKey {
            A_bytes: VerificationKeyBytes::from(identity_bytes),
            minus_A: -identity,
        }
    }
}

#[cfg(feature = "zeroize")]
impl DefaultIsZeroes for VerificationKey {}

impl From<VerificationKey> for [u8; 32] {
    fn from(vk: VerificationKey) -> [u8; 32] {
        vk.A_bytes.0
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = Error;
    #[allow(non_snake_case)]
    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
        //   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
        let A = CompressedEdwardsY(bytes.0)
            .decompress()
            .ok_or(Error::MalformedPublicKey)?;

        Ok(VerificationKey {
            A_bytes: bytes,
            minus_A: -A,
        })
    }
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKey, Error> {
        VerificationKeyBytes::try_from(slice).and_then(|vkb| vkb.try_into())
    }
}

impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePublicKey for VerificationKey {
    /// Serialize [`VerificationKey`] to an ASN.1 DER-encoded document.
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        SubjectPublicKeyInfoRef {
            algorithm: ALGORITHM_ID,
            subject_public_key: BitStringRef::from_bytes(&self.A_bytes.0[..])?,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl DecodePublicKey for VerificationKey {
    /// Deserialize [`VerificationKey`] from ASN.1 DER bytes (32 bytes).
    fn from_public_key_der(bytes: &[u8]) -> Result<Self, pkcs8::spki::Error> {
        let spki = SubjectPublicKeyInfoRef::try_from(bytes)?;
        let pk_bytes = verification_key_bytes_from_spki(spki)?;
        Self::try_from(pk_bytes).map_err(|_| SpkiError::KeyMalformed)
    }
}

impl Verifier<Signature> for VerificationKey {
    /// Verify a [`Signature`] object against a given [`VerificationKey`].
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519::signature::Error> {
        self.verify(signature, message)
            .map_err(|_| ed25519::signature::Error::new())
    }
}

impl VerificationKey {
    fn challenge_scalar(&self, signature: &Signature, msg: &[u8]) -> Scalar {
        scalar_from_sha512(
            Sha512::default()
                .chain(&signature.r_bytes()[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        )
    }

    /// Verify a purported `signature` on the given `msg`.
    ///
    /// This is the default verification mode and uses the HEEA-accelerated
    /// verification path with Zebra / ZIP-215 semantics.
    ///
    /// ## Zcash-specific consensus properties
    ///
    /// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
    /// [ZIP215].  The verification criteria for an (encoded) signature `(R_bytes, s_bytes)` with
    /// (encoded) verification key `A_bytes` are:
    ///
    /// * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
    ///   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
    ///
    /// * `s_bytes` MUST represent an integer `s` less than `l`, the order of the prime-order
    ///   subgroup of Curve25519;
    ///
    /// * the verification equation `[8][s]B = [8]R + [8][k]A` MUST be satisfied;
    ///
    /// * the alternate verification equation `[s]B = R + [k]A`, allowed by RFC 8032, MUST NOT be
    ///   used.
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
    /// [ZIP215]: https://zips.z.cash/zip-0215
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_zebra(signature, msg)
    }

    /// Verify a signature using HEEA with Zebra / ZIP-215 semantics.
    ///
    /// This implements the algorithm from "Accelerating EdDSA Signature Verification
    /// with Faster Scalar Size Halving" (TCHES 2025).
    ///
    /// The decomposition returns ρ and τ such that either ρ ≡ τh (mod ℓ) or
    /// ρ ≡ -τh (mod ℓ). The standard verification equation sB = R + hA is
    /// multiplied by τ and the sign of A is selected according to `flip_h`.
    ///
    /// Both ρ and τ are approximately half the size of h.
    ///
    /// We then decompose τs into two 128-bit scalars:
    /// τs = τs_hi * 2^128 + τs_lo
    ///
    /// The resulting equation can be checked with a 4-variable MSM with
    /// half-size scalars.
    #[allow(non_snake_case)]
    pub fn verify_zebra(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_zebra_prehashed(signature, self.challenge_scalar(signature, msg))
    }

    #[allow(non_snake_case)]
    pub(crate) fn verify_zebra_prehashed(
        &self,
        signature: &Signature,
        h: Scalar,
    ) -> Result<(), Error> {
        // Generate half-size scalars ρ and τ. If flip_h is false, then
        // ρ ≡ τh (mod ℓ). If flip_h is true, then ρ ≡ -τh (mod ℓ), so the
        // sign of A is flipped below.
        let (rho, tau, flip_h) = h.heea_decompose();

        // Extract s from the signature
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        // Decode R from the signature
        let neg_R = -CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;

        // Standard verification checks: sB = R + hA.
        //
        // We verify:
        //   [8] τs B + [8] τ (-R) + [8] ρ A_term == 0
        // where A_term is -A when ρ ≡ τh and A when ρ ≡ -τh.

        // Compute τs
        let ts = tau * s;
        let A = if flip_h { -self.minus_A } else { self.minus_A };
        // HEEA decomposition guarantees tau and rho fit the optimized
        // 128/128/256-bit multiplication path.
        let result = crate::backend::vartime_triple_base_mul_128_128_256_prechecked(
            &tau, &neg_R, &rho, &A, &ts,
        );

        if result.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a signature with dalek-style canonical-`R` byte comparison.
    ///
    /// This recomputes the expected canonical `R` encoding and compares it to the
    /// signature's `R` bytes.
    ///
    /// This helper also preserves this crate's legacy compatibility filters: it
    /// rejects an all-zero encoded public key and the known legacy-excluded `R`
    /// encodings before running the canonical-`R` comparison. Because of those
    /// extra checks, this is not a byte-for-byte clone of every `ed25519-dalek`
    /// release.
    ///
    /// Note that dalek-style canonical-`R` comparison is incompatible with the HEEA
    /// transformed equation because the transformed check does not preserve the
    /// original `R` encoding needed for the byte comparison.
    #[allow(non_snake_case)]
    pub fn verify_dalek(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_dalek_prehashed(signature, self.challenge_scalar(signature, msg))
    }

    #[allow(non_snake_case)]
    fn verify_dalek_prehashed(&self, signature: &Signature, h: Scalar) -> Result<(), Error> {
        if self.A_bytes.0 == [0; 32] || r_encoding_is_legacy_excluded(signature.r_bytes()) {
            return Err(Error::InvalidSignature);
        }

        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        let expected_R =
            EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &self.minus_A, &s).compress();

        if expected_R.as_bytes() == signature.r_bytes() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
