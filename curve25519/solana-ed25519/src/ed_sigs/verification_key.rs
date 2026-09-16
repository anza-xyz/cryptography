// -*- mode: rust; -*-
//
// This file is part of solana-ed25519's ed_sigs module, forked from ed25519-zebra.
// Original ed25519-zebra code: Copyright (c) Zcash Foundation contributors
// Modifications for HEEA: Copyright (c) 2025 curve25519-sol contributors
// The ed25519-zebra portions are used under the MIT branch of its `MIT OR
// Apache-2.0` license; see the crate-root LICENSE-MIT. The crate as a whole is
// BSD-3-Clause (see LICENSE) with third-party notices in ACKNOWLEDGEMENTS.md.
//
// Modifications from ed25519-zebra:
// - Added `verify_simd0376`, an accelerated verification path using the HEEA
//   scalar decomposition from curve25519-sol's `HEEADecomposition` trait.
//   See "Accelerating EdDSA Signature Verification with Faster Scalar Size
//   Halving" (TCHES 2025) for the algorithm.
// - `verify` dispatches to `verify_simd0376`, which applies SIMD-0376
//   semantics: ZIP-215's cofactored equation, plus explicit rejection of
//   non-canonical encodings and of small-order `A` and `R`.

use crate::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{HEEADecomposition, IsIdentity},
};
use core::convert::{TryFrom, TryInto};
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

use super::{Error, accepts_point_encoding};

/// The length of an ed25519 `VerificationKey`, in bytes.
pub const VERIFICATION_KEY_LENGTH: usize = 32;

#[cfg(feature = "pkcs8")]
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112"); // RFC 8410
#[cfg(feature = "pkcs8")]
const ALGORITHM_ID: AlgorithmIdentifierRef<'_> = AlgorithmIdentifierRef {
    oid: OID,
    parameters: None,
};

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
/// # use solana_ed25519::ed_sigs::*;
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
/// ## Validation performed here
///
/// Constructing a `VerificationKey` only requires that `A_bytes` decode to a
/// point on the twisted Edwards form of Curve25519. Non-canonical and
/// small-order encodings are deliberately still accepted at this stage: the
/// two verification rules this type offers disagree about them, and
/// [`VerificationKey::verify_dalek`] must stay accept/reject identical to
/// `ed25519-dalek`'s `verify_strict`, which also decodes `A` permissively.
///
/// The SIMD-0376 canonicity and small-order rejections are therefore applied
/// in [`VerificationKey::verify_simd0376`], not in the constructor.
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
        // Only step 4 of the SIMD-0376 algorithm (on-curve decoding) happens
        // here; steps 1 and 5 for `A` are applied in `verify_simd0376`. See
        // the type-level docs for why.
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
        super::challenge_scalar(signature.r_bytes(), &self.A_bytes.0, msg)
    }

    /// Verify a purported `signature` on the given `msg`.
    ///
    /// This is the default verification mode and dispatches to
    /// [`VerificationKey::verify_simd0376`].
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_simd0376(signature, msg)
    }

    /// Verify a signature under [SIMD-0376] semantics, using the
    /// HEEA-accelerated verification equation.
    ///
    /// ## Consensus properties
    ///
    /// For a message `M`, a 32-byte verification key encoding `A_bytes` and a
    /// 64-byte signature split into `R_bytes` and `s_bytes`:
    ///
    /// 1. `A_bytes` MUST be a canonical encoding;
    /// 2. `R_bytes` MUST be a canonical encoding;
    /// 3. `s_bytes` MUST represent an integer `s` less than `ℓ`, the order of
    ///    the prime-order subgroup of Curve25519;
    /// 4. `A_bytes` and `R_bytes` MUST decode to points on the twisted Edwards
    ///    form of Curve25519;
    /// 5. neither `A` nor `R` may be small-order, i.e. satisfy `[8]P = O`;
    /// 6. `h` is `SHA512(R_bytes || A_bytes || M)` reduced mod `ℓ`;
    /// 7. the cofactored equation `[8][s]B - [8]R - [8][h]A = O` MUST be
    ///    satisfied. The cofactorless equation `[s]B = R + [h]A`, allowed by
    ///    RFC 8032 and used by `verify_strict`, MUST NOT be used.
    ///
    /// This is [ZIP-215]'s cofactored equation, but it is deliberately *not*
    /// ZIP-215: ZIP-215 accepts non-canonical encodings and small-order `A`,
    /// which on Solana would make `Pubkey::default()` — the all-zero encoding,
    /// which is also the System Program ID — a signable public key. Because
    /// the cofactored equation annihilates every small-order component, a
    /// small-order `A` that step 5 let through would verify the all-zero
    /// signature on *every* message.
    ///
    /// Steps 1-5 are per-signature and independent of any batch, so they can
    /// be applied before a signature enters a batched multiscalar
    /// multiplication; the `batch` module does exactly that. It is the
    /// cofactorless equation, not these checks, that makes batch verification
    /// of `verify_strict` semantics impossible.
    ///
    /// ## Implementation
    ///
    /// Step 7 uses the algorithm from "Accelerating EdDSA Signature
    /// Verification with Faster Scalar Size Halving" (TCHES 2025).
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
    ///
    /// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
    /// [ZIP-215]: https://zips.z.cash/zip-0215
    #[allow(non_snake_case)]
    pub fn verify_simd0376(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.verify_simd0376_prehashed(signature, self.challenge_scalar(signature, msg))
    }

    #[allow(non_snake_case)]
    pub(crate) fn verify_simd0376_prehashed(
        &self,
        signature: &Signature,
        h: Scalar,
    ) -> Result<(), Error> {
        // Steps 1 and 5 for `A`: canonical encoding, not small-order.
        if !accepts_point_encoding(&self.A_bytes.0) {
            return Err(Error::MalformedPublicKey);
        }

        // Steps 2 and 5 for `R`. Both of these are byte-string tests, so they
        // run before `R` is decompressed, which costs a square root.
        if !accepts_point_encoding(signature.r_bytes()) {
            return Err(Error::InvalidSignature);
        }

        // Step 3: `s` must be fully reduced.
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        // Step 4: decode `R`. `A` was decoded when this key was constructed.
        let neg_R = -CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;

        // Generate half-size scalars ρ and τ. If flip_h is false, then
        // ρ ≡ τh (mod ℓ). If flip_h is true, then ρ ≡ -τh (mod ℓ), so the
        // sign of A is flipped below.
        let (rho, tau, flip_h) = h.heea_decompose();

        // Step 7. Standard verification checks: sB = R + hA.
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

    /// Verify a signature with the strict, non-cofactored rules of
    /// [`ed25519_dalek::VerifyingKey::verify_strict`].
    ///
    /// This is the pre-SIMD-0376 verification rule, kept so that a validator
    /// gating SIMD-0376 can evaluate either rule, and is accept/reject
    /// identical to `verify_strict`:
    ///
    /// * `s` MUST be canonically encoded (i.e. reduced mod `ℓ`);
    /// * `R` MUST decode to a point on the curve;
    /// * neither `A` nor `R` may be of small order (i.e. of order dividing the
    ///   cofactor 8) — this is what makes a signature unforgeable without the
    ///   private scalar, since `[h](-A)` takes only `ord(A)` values when `A` is
    ///   of small order, so an attacker with no private key can hit the
    ///   verification equation by grinding the message;
    /// * the recomputed canonical encoding of `R` MUST equal the signature's
    ///   `R` bytes, which additionally rejects every non-canonical `R`.
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
        // Reject small-order `A` and small-order `R`, exactly as
        // `verify_strict` does. These are algebraic tests on purpose: a
        // blacklist of encodings is not equivalent, because every low-order
        // point has both a sign-bit-clear and a sign-bit-set encoding, and
        // several also have non-canonical encodings.
        //
        // `A` is checked through `minus_A`, which has the same order as `A`.
        // Cheap tests first: `is_small_order` is three doublings, whereas
        // decompressing `R` costs a square root.
        if self.minus_A.is_small_order() {
            return Err(Error::InvalidSignature);
        }

        let R = CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;
        if R.is_small_order() {
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
