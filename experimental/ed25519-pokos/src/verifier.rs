//! Verifier-side entry points for the POKOS proof envelope.
//!
//! Verification is split into two independent layers, either of which can
//! reject the proof:
//!
//! 1. **STARK verification** — checks the Plonky3 proof against the public
//!    statement `(commit_of_seed, hash_of_sk)`.  A valid proof guarantees
//!    that the prover knew a seed that produced both values via the prescribed
//!    SHA-512 derivation chain.
//!
//! 2. **Ed25519 authentication** — checks the signature over the
//!    `authentication_transcript` against `authentication_key`.  A valid
//!    signature guarantees that the holder of the Ed25519 key derived from
//!    `sk_seed` authorized this specific proof.
//!
//! Both checks must pass for [`verify_pokos`] to return `Ok(())`.

use crate::sha512::{
    PrivateSeedChainPublic, SealedPrivateSeedChainProof, verify_private_seed_chain_statement,
};
use crate::{
    DeserializeError, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, PROOF_FORMAT_MAGIC,
    SeedChainProofEnvelope, SeedChainStatement, Sha512ProofBundle, VerifyError,
    authentication_transcript,
};
use curve25519::ed_sigs::{Signature, VerificationKey, VerificationKeyBytes};

/// Verifies a [`SeedChainProofEnvelope`].
///
/// Performs two checks in order:
/// 1. Verifies the STARK proof against the public statement.
/// 2. Verifies the Ed25519 signature over the authentication transcript.
///
/// # Errors
///
/// - [`VerifyError::InvalidSkDerivationProof`] if the STARK proof is invalid
///   or does not match `proof.statement`.
/// - [`VerifyError::AuthenticationSignatureInvalid`] if the Ed25519 signature
///   is invalid or was made with a different key.
pub fn verify_pokos(proof: &SeedChainProofEnvelope) -> Result<(), VerifyError> {
    verify_sha512_bundle(&proof.sha512_proof, proof.statement)?;

    let transcript = authentication_transcript(proof.statement);
    let verification_key = VerificationKey::try_from(proof.authentication_key)
        .map_err(|_| VerifyError::AuthenticationSignatureInvalid)?;
    verification_key
        .verify(&proof.authentication_signature, &transcript)
        .map_err(|_| VerifyError::AuthenticationSignatureInvalid)
}

/// Serializes a [`SeedChainProofEnvelope`] to bytes.
///
/// Wire format (big-endian lengths):
/// ```text
/// [magic: 8]
/// [commit_of_seed: 64]
/// [hash_of_sk: 64]
/// [sha512_proof_len: 8] [sha512_proof: N]
/// [authentication_key: 32]
/// [authentication_signature: 64]
/// ```
///
/// The serialized form is self-describing: the magic bytes identify the
/// format version, and all variable-length fields are prefixed with their
/// 64-bit big-endian byte count.
pub fn serialize_proof(proof: &SeedChainProofEnvelope) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROOF_FORMAT_MAGIC);
    bytes.extend_from_slice(&proof.statement.commit_of_seed);
    bytes.extend_from_slice(&proof.statement.hash_of_sk);
    bytes.extend_from_slice(&(proof.sha512_proof.sealed_proof.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&proof.sha512_proof.sealed_proof);
    bytes.extend_from_slice(proof.authentication_key.as_ref());
    bytes.extend_from_slice(&proof.authentication_signature.to_bytes());
    bytes
}

/// Deserializes a [`SeedChainProofEnvelope`] from bytes produced by [`serialize_proof`].
///
/// # Errors
///
/// - [`DeserializeError::InvalidMagic`] if the leading bytes are not
///   `EPKOS001`.
/// - [`DeserializeError::Truncated`] if the byte slice ends before all fields
///   have been read, or if a length prefix points past the end of the slice.
/// - [`DeserializeError::InvalidSignature`] if the Ed25519 signature bytes are
///   structurally invalid.
/// - [`DeserializeError::TrailingBytes`] if there are extra bytes after the
///   last expected field.
pub fn deserialize_proof(bytes: &[u8]) -> Result<SeedChainProofEnvelope, DeserializeError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.read_exact(PROOF_FORMAT_MAGIC.len())? != *PROOF_FORMAT_MAGIC {
        return Err(DeserializeError::InvalidMagic);
    }

    let statement = SeedChainStatement {
        commit_of_seed: cursor.read_array()?,
        hash_of_sk: cursor.read_array()?,
    };
    let sha512_proof = Sha512ProofBundle {
        sealed_proof: cursor.read_vec()?,
    };
    let authentication_key =
        VerificationKeyBytes::from(cursor.read_array::<ED25519_PUBLIC_KEY_LEN>()?);
    let signature_bytes = cursor.read_array::<ED25519_SIGNATURE_LEN>()?;
    let authentication_signature =
        Signature::from_slice(&signature_bytes).map_err(|_| DeserializeError::InvalidSignature)?;

    if !cursor.is_at_end() {
        return Err(DeserializeError::TrailingBytes);
    }

    Ok(SeedChainProofEnvelope {
        statement,
        sha512_proof,
        authentication_key,
        authentication_signature,
    })
}

/// Verifies the Plonky3 STARK proof inside `bundle` against the public `statement`.
///
/// Returns `Ok(())` if the proof is valid; `Err(VerifyError::InvalidSkDerivationProof)`
/// otherwise.
fn verify_sha512_bundle(
    bundle: &Sha512ProofBundle,
    statement: SeedChainStatement,
) -> Result<(), VerifyError> {
    let verified = verify_private_seed_chain_statement(
        &SealedPrivateSeedChainProof {
            sealed_proof: bundle.sealed_proof.clone(),
        },
        PrivateSeedChainPublic {
            commit_of_seed: statement.commit_of_seed,
            hash_of_sk: statement.hash_of_sk,
        },
    );
    if verified {
        Ok(())
    } else {
        Err(VerifyError::InvalidSkDerivationProof)
    }
}

/// Minimal forward-only byte reader used during deserialization.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, DeserializeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DeserializeError::Truncated)?;
        if end > self.bytes.len() {
            return Err(DeserializeError::Truncated);
        }
        let slice = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializeError> {
        if self.offset + N > self.bytes.len() {
            return Err(DeserializeError::Truncated);
        }
        let mut out = [0_u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }

    fn read_u64(&mut self) -> Result<u64, DeserializeError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, DeserializeError> {
        let len = self.read_u64()? as usize;
        self.read_exact(len)
    }

    fn is_at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
