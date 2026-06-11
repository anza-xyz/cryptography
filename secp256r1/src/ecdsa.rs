use crate::{
    Error, Result,
    constants::{
        COMPRESSED_SEC1_PUBLIC_KEY_LEN, DIGEST_LEN, ORDER_BYTES, UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN,
    },
    field::FieldElement,
    group::{AffinePoint, ProjectivePoint},
    scalar::Scalar,
};
use core::fmt;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// An ECDSA signature over the P-256 curve.
///
/// A signature consists of two scalars, `r` and `s`, each in `[1, n-1]`
/// where `n` is the group order. Use [`from_der`][Self::from_der] or
/// [`from_slice`][Self::from_slice] to parse, and [`to_der`][Self::to_der]
/// or [`to_bytes`][Self::to_bytes] to serialize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    r: Scalar,
    s: Scalar,
}

impl Signature {
    /// Builds a signature from canonical big-endian 32-byte `r` and `s` scalars.
    ///
    /// Returns an error if either scalar is zero or not in canonical form
    /// (i.e. ≥ the group order `n`).
    pub fn from_scalars(r: [u8; DIGEST_LEN], s: [u8; DIGEST_LEN]) -> Result<Self> {
        let r = Scalar::from_be_bytes(r)
            .filter(|r| !r.is_zero())
            .ok_or_else(|| Error::InvalidInput("invalid ECDSA r scalar".to_owned()))?;
        let s = Scalar::from_be_bytes(s)
            .filter(|s| !s.is_zero())
            .ok_or_else(|| Error::InvalidInput("invalid ECDSA s scalar".to_owned()))?;

        Ok(Self { r, s })
    }

    /// Parses a DER-encoded ECDSA signature.
    ///
    /// Enforces strict/minimal DER: no trailing bytes, no leading zero bytes
    /// in integers beyond the required sign byte, no negative integers.
    pub fn from_der(signature_der: &[u8]) -> Result<Self> {
        let mut parser = DerParser::new(signature_der);
        parser.expect_byte(0x30)?;
        let sequence_len = parser.read_len()?;
        let sequence_end = parser
            .position
            .checked_add(sequence_len)
            .ok_or_else(|| Error::InvalidInput("invalid DER sequence length".to_owned()))?;

        if sequence_end != signature_der.len() {
            return Err(Error::InvalidInput(
                "DER signature has trailing data".to_owned(),
            ));
        }

        let r = parser.read_integer_32()?;
        let s = parser.read_integer_32()?;

        if parser.position != sequence_end {
            return Err(Error::InvalidInput(
                "DER signature has trailing sequence data".to_owned(),
            ));
        }

        Self::from_scalars(r, s)
    }

    /// Parses a fixed-width `r || s` ECDSA signature.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; 64] = bytes
            .try_into()
            .map_err(|_| Error::InvalidInput("expected 64-byte signature".to_owned()))?;
        let mut r = [0u8; DIGEST_LEN];
        let mut s = [0u8; DIGEST_LEN];
        r.copy_from_slice(&bytes[..DIGEST_LEN]);
        s.copy_from_slice(&bytes[DIGEST_LEN..]);
        Self::from_scalars(r, s)
    }

    /// Returns the fixed-width `r || s` encoding.
    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..DIGEST_LEN].copy_from_slice(&self.r.to_be_bytes());
        out[DIGEST_LEN..].copy_from_slice(&self.s.to_be_bytes());
        out
    }

    /// Returns the DER encoding of this signature.
    pub fn to_der(self) -> DerSignature {
        let mut out = [0u8; 72];
        let r = self.r.to_be_bytes();
        let s = self.s.to_be_bytes();
        let r_len = write_der_integer(&mut out[2..], r);
        let s_len = write_der_integer(&mut out[2 + r_len..], s);
        out[0] = 0x30;
        out[1] = (r_len + s_len) as u8;

        DerSignature {
            bytes: out,
            len: 2 + r_len + s_len,
        }
    }

    /// Returns the `r` scalar.
    #[inline]
    pub fn r(self) -> Scalar {
        self.r
    }

    /// Returns the `s` scalar.
    #[inline]
    pub fn s(self) -> Scalar {
        self.s
    }
}

/// A DER-encoded ECDSA signature, at most 72 bytes.
///
/// Produced by [`Signature::to_der`]. Use [`as_bytes`][Self::as_bytes] to
/// obtain the encoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerSignature {
    bytes: [u8; 72],
    len: usize,
}

impl DerSignature {
    /// Returns this DER signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for DerSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A SEC1-encoded public key, either compressed (33 bytes) or uncompressed (65 bytes).
///
/// Produced by [`VerifyingKey::to_encoded_point`]. Use
/// [`as_bytes`][Self::as_bytes] to obtain the encoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedPoint {
    bytes: [u8; UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN],
    len: usize,
}

impl EncodedPoint {
    /// Returns this encoded point as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for EncodedPoint {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// ECDSA signing key for secp256r1/P-256.
///
/// # Security
///
/// Public-key derivation and signing currently use variable-time scalar
/// multiplication with secret-dependent values. This type is intended for
/// benchmarking and experimentation, not production signing in side-channel
/// exposed environments.
#[derive(Clone)]
pub struct SigningKey {
    secret: Scalar,
    verifying_key: VerifyingKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("secret", &"<redacted>")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

impl SigningKey {
    /// Generates a signing key using rejection sampling.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let mut bytes = [0u8; DIGEST_LEN];
            rng.fill_bytes(&mut bytes);
            let key = Self::from_bytes(bytes);
            bytes.zeroize();
            if let Ok(key) = key {
                return key;
            }
        }
    }

    /// Builds a signing key from a canonical 32-byte scalar.
    ///
    /// This derives the corresponding verifying key using variable-time scalar
    /// multiplication.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut bytes: [u8; DIGEST_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidInput("expected 32-byte signing key".to_owned()))?;
        let key = Self::from_bytes(bytes);
        bytes.zeroize();
        key
    }

    /// Builds a signing key from a canonical 32-byte scalar.
    ///
    /// This derives the corresponding verifying key using variable-time scalar
    /// multiplication.
    pub fn from_bytes(mut bytes: [u8; DIGEST_LEN]) -> Result<Self> {
        let Some(secret) = Scalar::from_be_bytes(bytes).filter(|secret| !secret.is_zero()) else {
            bytes.zeroize();
            return Err(Error::InvalidInput("invalid signing key scalar".to_owned()));
        };
        bytes.zeroize();
        let mut scalar_bytes = secret.to_be_bytes();
        let public_key = ProjectivePoint::mul_generator_vartime(scalar_bytes).to_affine();
        scalar_bytes.zeroize();

        Ok(Self {
            secret,
            verifying_key: VerifyingKey { public_key },
        })
    }

    /// Returns the verifying key corresponding to this signing key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns this signing key as a canonical big-endian 32-byte scalar.
    ///
    /// The caller is responsible for clearing the returned bytes when they are
    /// no longer needed.
    pub fn to_bytes(&self) -> [u8; DIGEST_LEN] {
        self.secret.to_be_bytes()
    }

    /// Signs a message using SHA-256 and deterministic RFC6979 nonces.
    ///
    /// Signing uses variable-time scalar multiplication for the secret nonce.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_prehash(&Sha256::digest(message))
            .expect("SHA-256 output has the expected length")
    }

    /// Signs a 32-byte message digest using deterministic RFC6979 nonces.
    ///
    /// Signing uses variable-time scalar multiplication for the secret nonce.
    pub fn sign_prehash(&self, digest: &[u8]) -> Result<Signature> {
        let digest = digest_32(digest)?;
        let z = Scalar::from_be_bytes_reduced(digest);
        let mut secret = self.secret.to_be_bytes();
        let mut nonce = Rfc6979::new(secret, digest);
        secret.zeroize();

        loop {
            let mut k = nonce.next();
            let mut k_bytes = k.to_be_bytes();
            let r = scalar_from_x_coordinate(
                ProjectivePoint::mul_generator_vartime(k_bytes).to_affine(),
            );
            k_bytes.zeroize();

            if r.is_zero() {
                k.zeroize();
                nonce.retry();
                continue;
            }

            let Some(mut k_inv) = k.invert() else {
                k.zeroize();
                nonce.retry();
                continue;
            };
            let s = k_inv * (z + r * self.secret);

            if !s.is_zero() {
                k.zeroize();
                k_inv.zeroize();
                return Ok(Signature { r, s });
            }

            k.zeroize();
            k_inv.zeroize();
            nonce.retry();
        }
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// ECDSA verifying key for secp256r1/P-256.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    public_key: AffinePoint,
}

impl VerifyingKey {
    /// Builds a verifying key from compressed or uncompressed SEC1 public key bytes.
    pub fn from_sec1_bytes(public_key_sec1: &[u8]) -> Result<Self> {
        let public_key = match public_key_sec1.len() {
            UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN => {
                let bytes = public_key_sec1
                    .try_into()
                    .expect("length checked above for uncompressed SEC1 key");
                AffinePoint::from_sec1_uncompressed(bytes)
            }
            COMPRESSED_SEC1_PUBLIC_KEY_LEN => {
                let bytes = public_key_sec1
                    .try_into()
                    .expect("length checked above for compressed SEC1 key");
                AffinePoint::from_sec1_compressed(bytes)
            }
            _ => None,
        }
        .ok_or_else(|| Error::InvalidInput("invalid secp256r1 public key".to_owned()))?;

        Ok(Self { public_key })
    }

    /// Returns this public key as a SEC1-encoded point.
    ///
    /// Pass `compress = false` for the uncompressed 65-byte `0x04 || X || Y`
    /// encoding, or `compress = true` for the compressed 33-byte
    /// `0x02/0x03 || X` encoding.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        let uncompressed = self
            .public_key
            .to_sec1_uncompressed()
            .expect("verifying keys are never identity");

        if !compress {
            return EncodedPoint {
                bytes: uncompressed,
                len: UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN,
            };
        }

        let mut bytes = [0u8; UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN];
        let y = self
            .public_key
            .y()
            .expect("verifying keys are never identity");
        bytes[0] = if y.to_be_bytes()[DIGEST_LEN - 1] & 1 == 0 {
            0x02
        } else {
            0x03
        };
        bytes[1..33].copy_from_slice(&uncompressed[1..33]);
        EncodedPoint { bytes, len: 33 }
    }

    /// Verifies an ECDSA signature over a message using SHA-256.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verify_prehash(&Sha256::digest(message), signature)
    }

    /// Verifies an ECDSA signature over a 32-byte message digest.
    pub fn verify_prehash(&self, digest: &[u8], signature: &Signature) -> Result<()> {
        let digest = digest_32(digest)?;
        if self.verify_digest_signature(digest, signature) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verifies a DER-encoded ECDSA signature over a 32-byte message digest.
    pub fn verify_prehashed_der(&self, digest: &[u8], signature_der: &[u8]) -> Result<()> {
        let signature = Signature::from_der(signature_der)?;
        self.verify_prehash(digest, &signature)
    }

    fn verify_digest_signature(&self, digest: [u8; DIGEST_LEN], signature: &Signature) -> bool {
        let z = Scalar::from_be_bytes_reduced(digest);
        let Some(w) = signature.s.invert() else {
            return false;
        };
        let u1 = z * w;
        let u2 = signature.r * w;
        let point = ProjectivePoint::mul_generator_vartime(u1.to_be_bytes())
            + ProjectivePoint::from_affine(self.public_key)
                .mul_scalar_wnaf6_vartime(u2.to_be_bytes());

        !point.is_identity() && projective_x_matches_signature_r(point, signature.r)
    }
}

fn digest_32(digest: &[u8]) -> Result<[u8; DIGEST_LEN]> {
    digest.try_into().map_err(|_| Error::InvalidDigestLength {
        expected: DIGEST_LEN,
        actual: digest.len(),
    })
}

fn scalar_from_x_coordinate(point: AffinePoint) -> Scalar {
    let x = point.x().expect("nonzero scalar multiple of generator");
    Scalar::from_be_bytes_reduced(x.to_be_bytes())
}

fn write_der_integer(out: &mut [u8], bytes: [u8; DIGEST_LEN]) -> usize {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(DIGEST_LEN - 1);
    let integer = &bytes[first_nonzero..];

    out[0] = 0x02;
    if integer[0] & 0x80 != 0 {
        out[1] = (integer.len() + 1) as u8;
        out[2] = 0;
        out[3..3 + integer.len()].copy_from_slice(integer);
        3 + integer.len()
    } else {
        out[1] = integer.len() as u8;
        out[2..2 + integer.len()].copy_from_slice(integer);
        2 + integer.len()
    }
}

struct Rfc6979 {
    key: [u8; DIGEST_LEN],
    value: [u8; DIGEST_LEN],
}

impl Rfc6979 {
    fn new(mut secret: [u8; DIGEST_LEN], digest: [u8; DIGEST_LEN]) -> Self {
        let mut digest = Scalar::from_be_bytes_reduced(digest).to_be_bytes();
        let mut out = Self {
            key: [0u8; DIGEST_LEN],
            value: [1u8; DIGEST_LEN],
        };

        out.rekey(&[&[0x00], &secret, &digest]);
        out.update_value();
        out.rekey(&[&[0x01], &secret, &digest]);
        out.update_value();
        secret.zeroize();
        digest.zeroize();
        out
    }

    fn next(&mut self) -> Scalar {
        loop {
            self.update_value();

            if let Some(scalar) =
                Scalar::from_be_bytes(self.value).filter(|scalar| !scalar.is_zero())
            {
                return scalar;
            }

            self.retry();
        }
    }

    fn retry(&mut self) {
        self.rekey(&[&[0x00]]);
        self.update_value();
    }

    fn rekey(&mut self, parts: &[&[u8]]) {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC accepts keys of any size");
        mac.update(&self.value);
        for part in parts {
            mac.update(part);
        }
        let mut key = [0u8; DIGEST_LEN];
        key.copy_from_slice(&mac.finalize().into_bytes());
        self.key.copy_from_slice(&key);
        key.zeroize();
    }

    fn update_value(&mut self) {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC accepts keys of any size");
        mac.update(&self.value);
        let mut value = [0u8; DIGEST_LEN];
        value.copy_from_slice(&mac.finalize().into_bytes());
        self.value.copy_from_slice(&value);
        value.zeroize();
    }
}

impl Drop for Rfc6979 {
    fn drop(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

#[inline]
fn projective_x_matches_signature_r(point: ProjectivePoint, r: Scalar) -> bool {
    let r_bytes = r.to_be_bytes();
    let r_field = FieldElement::from_be_bytes(r_bytes).expect("r < group order < field prime");

    point.has_affine_x(r_field)
        || r_plus_order_field(r_bytes).is_some_and(|candidate| point.has_affine_x(candidate))
}

fn r_plus_order_field(r: [u8; DIGEST_LEN]) -> Option<FieldElement> {
    let mut out = [0u8; DIGEST_LEN];
    let mut carry = 0u16;

    for i in (0..DIGEST_LEN).rev() {
        let sum = r[i] as u16 + ORDER_BYTES[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }

    if carry == 0 {
        FieldElement::from_be_bytes(out)
    } else {
        None
    }
}

struct DerParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> DerParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<()> {
        let actual = self.read_byte()?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::InvalidInput("unexpected DER tag".to_owned()))
        }
    }

    fn read_len(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        let bytes = (first & 0x7f) as usize;
        if bytes == 0 || bytes > 2 {
            return Err(Error::InvalidInput(
                "unsupported DER length encoding".to_owned(),
            ));
        }

        let mut len = 0usize;
        for i in 0..bytes {
            let byte = self.read_byte()?;
            if i == 0 && byte == 0 {
                return Err(Error::InvalidInput(
                    "non-minimal DER length encoding".to_owned(),
                ));
            }
            len = (len << 8) | byte as usize;
        }

        if len < 128 {
            return Err(Error::InvalidInput(
                "non-minimal DER length encoding".to_owned(),
            ));
        }

        Ok(len)
    }

    fn read_integer_32(&mut self) -> Result<[u8; DIGEST_LEN]> {
        self.expect_byte(0x02)?;
        let len = self.read_len()?;
        if len == 0 {
            return Err(Error::InvalidInput("empty DER integer".to_owned()));
        }

        let integer = self.read_bytes(len)?;
        if integer[0] & 0x80 != 0 {
            return Err(Error::InvalidInput("negative DER integer".to_owned()));
        }

        let integer = if integer.len() > 1 && integer[0] == 0 {
            if integer[1] & 0x80 == 0 {
                return Err(Error::InvalidInput(
                    "non-minimal DER integer encoding".to_owned(),
                ));
            }
            &integer[1..]
        } else {
            integer
        };

        if integer.len() > DIGEST_LEN {
            return Err(Error::InvalidInput("oversized DER integer".to_owned()));
        }

        let mut out = [0u8; DIGEST_LEN];
        out[DIGEST_LEN - integer.len()..].copy_from_slice(integer);
        Ok(out)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| Error::InvalidInput("truncated DER input".to_owned()))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| Error::InvalidInput("invalid DER length".to_owned()))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or_else(|| Error::InvalidInput("truncated DER input".to_owned()))?;
        self.position = end;
        Ok(bytes)
    }
}
