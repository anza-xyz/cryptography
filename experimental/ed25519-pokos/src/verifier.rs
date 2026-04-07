//! Verifier-side entry points for the active proof envelope.
//!
//! Verification is intentionally split into two layers:
//! - verify the internal SHA-512 seed-chain proof against the public statement
//! - verify the outer Ed25519 signature over that same statement

use crate::sha512::{
    PrivateSeedChainPublic, SealedPrivateSeedChainProof, verify_private_seed_chain_statement,
};
use crate::{
    DeserializeError, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, PROOF_FORMAT_MAGIC,
    SeedChainProofEnvelope, SeedChainStatement, Sha512ProofBundle, VerifyError,
    authentication_transcript,
};
use curve25519::ed_sigs::{Signature, VerificationKey, VerificationKeyBytes};

pub fn verify_pokos(proof: &SeedChainProofEnvelope) -> Result<(), VerifyError> {
    verify_sha512_bundle(&proof.sha512_proof, proof.statement)?;

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
    bytes.extend_from_slice(&(proof.sha512_proof.sealed_proof.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&proof.sha512_proof.sealed_proof);
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
