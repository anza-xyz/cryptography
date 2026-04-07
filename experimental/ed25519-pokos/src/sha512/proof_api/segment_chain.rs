use bincode::Options;
use serde::{Deserialize, Serialize};

use super::{MAX_INNER_PROOF_BYTES, Sha512ProofSettings, Sha512StarkProof};

/// Maximum byte size accepted for a full serialized [`Sha512SegmentChainProof`].
///
/// This guards against allocation-based DoS attacks when deserializing
/// untrusted proof bytes.
const MAX_SEGMENT_CHAIN_PROOF_BYTES: usize = 64 * 1024 * 1024;

/// A Plonky3 STARK proof for the multi-segment seed chain, together with the
/// settings under which it was produced.
///
/// The `settings` are stored alongside the proof so that the verifier can
/// confirm it is checking the proof under the same parameters the prover used.
pub struct Sha512SegmentChainProof {
    /// The raw Plonky3 proof.
    pub proof: Sha512StarkProof,
    /// FRI and PoW parameters used when producing this proof.
    pub settings: Sha512ProofSettings,
}

/// Wire-serializable form of [`Sha512SegmentChainProof`].
///
/// The inner proof is first serialized to bytes independently so that its
/// length can be bounded before the outer envelope is deserialized.
#[derive(Serialize, Deserialize)]
struct SerializableSegmentChainProof {
    proof_bytes: Vec<u8>,
    settings: Sha512ProofSettings,
}

/// Serializes a [`Sha512SegmentChainProof`] to bytes using bincode.
///
/// The inner proof is serialized first; if it exceeds [`MAX_INNER_PROOF_BYTES`]
/// the call returns an error.  The outer envelope is checked against
/// [`MAX_SEGMENT_CHAIN_PROOF_BYTES`] after wrapping.
pub fn serialize_segment_chain_proof(proof: &Sha512SegmentChainProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    if proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner segment-chain proof exceeds configured size limit".to_string());
    }
    let serializable = SerializableSegmentChainProof {
        proof_bytes,
        settings: proof.settings,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SEGMENT_CHAIN_PROOF_BYTES {
        return Err("serialized segment-chain proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

/// Deserializes a [`Sha512SegmentChainProof`] from bytes.
///
/// Enforces size limits at both the outer and inner envelope levels before
/// any allocation-heavy deserialization begins.  Uses `reject_trailing_bytes`
/// to ensure there are no stray bytes in the input.
pub fn deserialize_segment_chain_proof(bytes: &[u8]) -> Result<Sha512SegmentChainProof, String> {
    if bytes.len() > MAX_SEGMENT_CHAIN_PROOF_BYTES {
        return Err("serialized segment-chain proof exceeds configured size limit".to_string());
    }
    let bincode_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SEGMENT_CHAIN_PROOF_BYTES as u64);
    let serializable: SerializableSegmentChainProof =
        bincode_opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner segment-chain proof exceeds configured size limit".to_string());
    }
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_INNER_PROOF_BYTES as u64);
    let proof: Sha512StarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    Ok(Sha512SegmentChainProof {
        proof,
        settings: serializable.settings,
    })
}
