//! Internal SHA-512 AIR and proof helpers for the `ed25519-pokos` seed-chain statement.
//!
//! The active proof path is the dedicated private seed-chain construction used to prove:
//! - `commit_of_seed = SHA512(domain_commit  || seed)`
//! - `sk_seed        = SHA512(domain_derive  || seed)[0..32]`
//! - `hash_of_sk     = SHA512(domain_hash_sk || sk_seed)`
//!
//! Witness types ([`PrivateSeedChainPublic`], `PrivateSeedChainWitness`) and block
//! helpers (`segment_block`) are defined in the outer `crate::private_seed_chain`
//! module and imported here, so each type has exactly one definition.
//!
//! [`Sha512Circuit`] and the AIR submodules provide the trace-generation and
//! constraint machinery; [`private_seed_chain`] wires them into the Plonky3
//! prover and verifier.

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
