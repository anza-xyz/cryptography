//! Verifier-side entry points for the active proof envelope.
//!
//! Verification is intentionally split into two layers:
//! - verify the internal SHA-512 seed-chain proof against the public statement
//! - verify the outer Ed25519 signature over that same statement

use crate::{
    BundleVerifyError, Cursor, DeserializeError, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    PROOF_FORMAT_MAGIC, SeedChainProofEnvelope, SeedChainStatement, VerifyError,
    append_sha512_bundle, authentication_transcript, read_sha512_bundle, verify_sha512_bundle,
};
use curve25519::ed_sigs::{Signature, VerificationKey, VerificationKeyBytes};

pub fn verify_pokos(proof: &SeedChainProofEnvelope) -> Result<(), VerifyError> {
    verify_sha512_bundle(&proof.sha512_proof, proof.statement).map_err(|err| match err {
        BundleVerifyError::InvalidProof => VerifyError::InvalidSkDerivationProof,
    })?;

    let transcript = authentication_transcript(proof.statement);
    let verification_key = VerificationKey::try_from(proof.authentication_key)
        .map_err(|_| VerifyError::AuthenticationSignatureInvalid)?;
    verification_key
        .verify(&proof.authentication_signature, &transcript)
        .map_err(|_| VerifyError::AuthenticationSignatureInvalid)
}

pub fn serialize_proof(proof: &SeedChainProofEnvelope) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROOF_FORMAT_MAGIC);
    bytes.extend_from_slice(&proof.statement.commit_of_seed);
    bytes.extend_from_slice(&proof.statement.hash_of_sk);
    append_sha512_bundle(&mut bytes, &proof.sha512_proof);
    bytes.extend_from_slice(proof.authentication_key.as_ref());
    bytes.extend_from_slice(&proof.authentication_signature.to_bytes());
    bytes
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<SeedChainProofEnvelope, DeserializeError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.read_exact(PROOF_FORMAT_MAGIC.len())? != *PROOF_FORMAT_MAGIC {
        return Err(DeserializeError::InvalidMagic);
    }

    let statement = SeedChainStatement {
        commit_of_seed: cursor.read_array()?,
        hash_of_sk: cursor.read_array()?,
    };
    let sha512_proof = read_sha512_bundle(&mut cursor)?;
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
