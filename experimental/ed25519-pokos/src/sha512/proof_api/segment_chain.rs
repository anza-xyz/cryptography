use bincode::Options;
use serde::{Deserialize, Serialize};

use super::{MAX_INNER_PROOF_BYTES, Sha512ProofSettings, Sha512StarkProof};

const MAX_SEGMENT_CHAIN_PROOF_BYTES: usize = 64 * 1024 * 1024;

pub struct Sha512SegmentChainProof {
    pub proof: Sha512StarkProof,
    pub settings: Sha512ProofSettings,
}

#[derive(Serialize, Deserialize)]
struct SerializableSegmentChainProof {
    proof_bytes: Vec<u8>,
    settings: Sha512ProofSettings,
}

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
