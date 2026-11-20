#![no_std]

//! One shielded pool on Solana, gated by the private-tx circuits.
//!
//! The pool is a single account holding the note commitment tree (an
//! append-only Poseidon Merkle tree, depth 32, the same tree
//! `circuits/merkle` defines), a ring of recent roots, the minted supply, and
//! the pool's authorities. Nullifiers are one PDA each, so a spent note
//! cannot be spent twice because its account already exists.
//!
//! Proofs are not verified here: every `Mint` and `Burn` CPIs the generic
//! Groth16 verifier program with the circuit's verifying-key account, whose
//! address the pool pins at initialization. This program only decides which
//! public inputs the proof must open to and what to do with them.
//!
//! Instruction data is `tag ‖ payload`; see [`instruction`] (host side) and
//! [`processor`] for the exact layouts. The pool wraps one SPL Token mint:
//! `Mint` is a shield (the depositor's tokens move into the pool's vault,
//! a note is created), `Transfer` moves value between notes inside the
//! pool, and `Burn` an unshield or forfeiture (the vault pays the
//! destination the proof was made for). Every output note comes with a
//! ciphertext for its recipient and one for the custodian's audit key.

pub mod error;
pub mod processor;
pub mod state;

#[cfg(feature = "instruction")]
pub mod instruction;

use pinocchio::Address;

/// This program. A placeholder, like the verifier's: generate your own
/// before deploying.
pub const ID: Address = Address::from_str_const("3sDoL7Tan84VmueUVRp1NRkhfPRF2z54ccf4J4LMHXdT");

/// The Groth16 verifier program every proof goes through.
pub const VERIFIER_ID: Address =
    Address::from_str_const("GrPeAM83MtRfR8NvbW3tMMSBzQ9BsmQrgLjLCQNwZW4P");

/// `Burn` takes eleven accounts; nothing takes more.
pub const MAX_ACCOUNTS: usize = 11;

#[cfg(all(
    any(target_os = "solana", target_arch = "bpf"),
    not(feature = "no-entrypoint")
))]
mod entrypoint {
    pinocchio::program_entrypoint!(crate::processor::process_instruction, {
        crate::MAX_ACCOUNTS
    });
    pinocchio::no_allocator!();
    pinocchio::nostd_panic_handler!();
}
