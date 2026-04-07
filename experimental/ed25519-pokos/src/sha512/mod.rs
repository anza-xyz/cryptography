//! Internal SHA-512 AIR and proof helpers for the `ed25519-pokos` seed-chain statement.
//!
//! This module no longer exposes the old generic single-block / full-message API. The active
//! proof path is the dedicated private seed-chain construction used to prove:
//! - `commit_of_seed = SHA512(domain_commit || seed)`
//! - `sk_seed = first_32_bytes(SHA512(domain_derive || seed))`
//! - `hash_of_sk = SHA512(domain_hash_sk || sk_seed)`
//!
//! The public verifier-facing statement is handled through [`private_seed_chain`], while
//! [`Sha512Circuit`] and the AIR submodules provide the trace and constraint machinery underneath.

mod air;
mod circuit;
mod constants;
mod ops;
mod private_seed_chain;
mod proof_api;
mod trace;

pub use circuit::Sha512Circuit;
pub use constants::INITIAL_STATE;
pub(crate) use proof_api::{
    Sha512ProofSettings, Sha512SegmentChainProof, Sha512StarkConfig,
    deserialize_segment_chain_proof, serialize_segment_chain_proof,
};

pub(crate) use private_seed_chain::{
    PrivateSeedChainPublic, SealedPrivateSeedChainProof, prove_private_seed_chain,
    verify_private_seed_chain_statement,
};
