// -*- mode: rust; -*-
//
// This file is part of ed25519-heea, a fork of ed25519-zebra.
// Original ed25519-zebra code: Copyright (c) Zcash Foundation contributors
// Modifications for HEEA: Copyright (c) 2025 curve25519-sol contributors
// See LICENSE-APACHE and LICENSE-MIT for licensing information.
//
// Modifications from ed25519-zebra:
// - Added `verify_heea`, an accelerated verification path using the HEEA
//   scalar decomposition from curve25519-sol's `HEEADecomposition` trait.
//   See "Accelerating EdDSA Signature Verification with Faster Scalar Size
//   Halving" (TCHES 2025) for the algorithm.
// - `verify` and all ZIP-215 consensus logic are unchanged from ed25519-zebra.

use crate::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{HEEADecomposition, IsIdentity},
};
use core::convert::{TryFrom, TryInto};
use sha2::{Sha512, digest::Update};
use zeroize::DefaultIsZeroes;

use ed25519::{Signature, signature::Verifier};

#[cfg(feature = "pkcs8")]
use pkcs8::der::asn1::BitStringRef;
#[cfg(feature = "pkcs8")]
use pkcs8::spki::{
    AlgorithmIdentifierRef, DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfoRef,
};
#[cfg(feature = "pkcs8")]
use pkcs8::{Document, ObjectIdentifier};

use super::Error;

/// The length of an ed25519 `VerificationKey`, in bytes.
pub const VERIFICATION_KEY_LENGTH: usize = 32;

/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of an Ed25519 verification key.
///
/// This is useful for representing an encoded verification key, while the
/// [`VerificationKey`] type in this library caches other decoded state used in
/// signature verification.
///
/// A `VerificationKeyBytes` can be used to verify a single signature using the
/// following idiom:
/// ```
/// use core::convert::TryFrom;
/// # use curve25519::ed_sigs::*;
/// # let msg = b"Zcash";
/// # let sk = SigningKey::new(rand::rng());
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

    fn try_from(spki: SubjectPublicKeyInfoRef) -> Result<VerificationKeyBytes, Error> {
        Ok(VerificationKeyBytes::try_from(spki.subject_public_key.as_bytes().unwrap()).unwrap())
    }
}

/// A valid Ed25519 verification key.
///
/// This is also called a public key by other implementations.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
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
        let alg_info = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // RFC 8410
            parameters: None,
        };
        SubjectPublicKeyInfoRef {
            algorithm: alg_info,
            subject_public_key: BitStringRef::from_bytes(&self.A_bytes.0[..])?,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl DecodePublicKey for VerificationKey {
    /// Deserialize [`VerificationKey`] from ASN.1 DER bytes (32 bytes).
    fn from_public_key_der(bytes: &[u8]) -> Result<Self, pkcs8::spki::Error> {
        let spki = SubjectPublicKeyInfoRef::try_from(bytes).unwrap();
        let pk_bytes = spki.subject_public_key.as_bytes().unwrap();
        Ok(Self::try_from(pk_bytes).unwrap())
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
        Scalar::from_hash(
            Sha512::default()
                .chain(&signature.r_bytes()[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        )
    }

    fn validate_decomposed_heea_params(
        h: &Scalar,
        (rho, tau, flip_h): (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        if tau == Scalar::ZERO
            || !Self::is_heea_half_size_scalar(&rho)
            || !Self::is_heea_half_size_scalar(&tau)
        {
            return Err(Error::InvalidSignature);
        }

        let expected_rho = tau * *h;
        let expected_rho = if flip_h { -expected_rho } else { expected_rho };

        if rho == expected_rho {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn is_heea_half_size_scalar(scalar: &Scalar) -> bool {
        scalar.as_bytes()[16..32].iter().all(|&byte| byte == 0)
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

    /// Verify a signature using caller-provided HEEA decomposition parameters
    /// with Zebra / ZIP-215 semantics.
    ///
    /// This is an alias for [`Self::relayer_verify_zebra`].
    pub fn relayer_verify(
        &self,
        signature: &Signature,
        msg: &[u8],
        heea_params: (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        self.relayer_verify_zebra(signature, msg, heea_params)
    }

    // ==============================
    //  zebra related methods
    // ==============================

    /// Verify a signature using HEEA with Zebra / ZIP-215 semantics.
    ///
    /// This implements the algorithm from "Accelerating EdDSA Signature Verification
    /// with Faster Scalar Size Halving" (TCHES 2025).
    ///
    /// The standard verification equation sB = R + hA is transformed to:
    /// τsB = τR + ρA where ρ ≡ τh (mod ℓ)
    ///
    /// Both ρ and τ are approximately half the size of h.
    ///
    /// We then decompose τs into two 128-bit scalars:
    /// τs = τs_hi * 2^128 + τs_lo
    ///
    /// The verification equation becomes:
    /// τs_lo B + τs_hi (2^128 B) = τR + ρA
    /// which can be done via 4-variable MSM with half-size scalars.
    #[allow(non_snake_case)]
    pub fn verify_zebra(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_zebra_prehashed(signature, self.challenge_scalar(signature, msg))
    }

    /// Verify a signature using caller-provided HEEA decomposition parameters.
    ///
    /// The `heea_params` tuple is `(rho, tau, flip_h)` from decomposing the
    /// challenge scalar `H(R_bytes || A_bytes || msg)`. This method checks that
    /// the supplied parameters match that challenge, then verifies the signature
    /// without recomputing the HEEA decomposition.
    ///
    /// This uses the same Zebra / ZIP-215 consensus semantics as
    /// [`Self::verify_zebra`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the signature is malformed, the
    /// supplied HEEA parameters do not match the message challenge, or the
    /// verification equation does not hold.
    pub fn relayer_verify_zebra(
        &self,
        signature: &Signature,
        msg: &[u8],
        heea_params: (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        let h = self.challenge_scalar(signature, msg);
        Self::validate_decomposed_heea_params(&h, heea_params)?;
        self.verify_zebra_with_decomposed_heea(signature, heea_params)
    }

    #[allow(non_snake_case)]
    pub(crate) fn verify_zebra_prehashed(
        &self,
        signature: &Signature,
        h: Scalar,
    ) -> Result<(), Error> {
        // Generate half-size scalars ρ and τ such that ρ ≡ τh (mod ℓ)
        // in order to have rho and tau approximately half the size of h
        // it is possible that we compute ρ ≡ -τh (mod ℓ)
        // this is indicated by `flip_h` flag being true,
        // in which case we will need to negate A later
        // let (rho, tau, flip_h) = crate::heea::generate_half_size_scalars(&h);
        self.verify_zebra_with_decomposed_heea(signature, h.heea_decompose())
    }

    #[allow(non_snake_case)]
    fn verify_zebra_with_decomposed_heea(
        &self,
        signature: &Signature,
        (rho, tau, flip_h): (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        // Extract s from the signature
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        // Decode R from the signature
        let neg_R = -CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;

        // Standard verification checks: sB = R + hA
        // Transformed verification: -τsB + τR + ρA == 0
        //
        // We verify:
        //  [8] τs B + [8] τ (-R) + [8] ρ (-A) == 0

        // Compute τs
        let ts = tau * s;
        let A = if flip_h { -self.minus_A } else { self.minus_A };
        // Compute the multi-scalar multiplication
        let result = EdwardsPoint::vartime_triple_scalar_mul_basepoint(&tau, &neg_R, &rho, &A, &ts);

        if result.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    // ==============================
    //  dalek related methods
    // ==============================

    /// Verify a signature with exact `ed25519-dalek`-style byte-level behavior.
    ///
    /// This recomputes the expected canonical `R` encoding and compares it to the
    /// signature's `R` bytes, matching dalek's ordinary verification behavior.
    ///
    /// Note that exact dalek-compatible behavior is incompatible with the HEEA
    /// transformed equation because the transformed check does not preserve the
    /// original `R` encoding needed for the byte comparison.
    #[allow(non_snake_case)]
    pub fn verify_dalek(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_dalek_prehashed(signature, self.challenge_scalar(signature, msg))
    }

    /// Verify a signature with `ed25519-dalek`-style byte-level behavior using
    /// caller-provided HEEA decomposition parameters.
    ///
    /// The `heea_params` tuple is `(rho, tau, flip_h)` from decomposing the
    /// challenge scalar `H(R_bytes || A_bytes || msg)`. This method checks that
    /// the supplied parameters match that challenge, then verifies the signature
    /// without recomputing the HEEA decomposition.
    ///
    /// This preserves the `ed25519-dalek`-compatible behavior of
    /// [`Self::verify_dalek`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the signature is malformed, the
    /// supplied HEEA parameters do not match the message challenge, or the
    /// verification equation does not hold.
    pub fn relayer_verify_dalek(
        &self,
        signature: &Signature,
        msg: &[u8],
        heea_params: (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        let h = self.challenge_scalar(signature, msg);
        Self::validate_decomposed_heea_params(&h, heea_params)?;
        self.verify_dalek_with_decomposed_heea(signature, heea_params)
    }

    #[allow(non_snake_case)]
    fn verify_dalek_prehashed(&self, signature: &Signature, h: Scalar) -> Result<(), Error> {
        self.verify_dalek_with_decomposed_heea(signature, h.heea_decompose())
    }

    #[allow(non_snake_case)]
    fn verify_dalek_with_decomposed_heea(
        &self,
        signature: &Signature,
        (rho, tau, flip_h): (Scalar, Scalar, bool),
    ) -> Result<(), Error> {
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        let r = CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;

        let ts = tau * s;
        let A = if flip_h { self.minus_A } else { -self.minus_A };
        let neg_ts = -ts;

        let result = EdwardsPoint::vartime_triple_scalar_mul_basepoint(&tau, &r, &rho, &A, &neg_ts);

        if result.is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
