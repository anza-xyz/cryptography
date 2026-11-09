//! Program errors, surfaced as `ProgramError::Custom(code)`.

use pinocchio::error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolError {
    /// The pool account's discriminator or length is wrong.
    InvalidPoolAccount = 0,
    /// The pool account is already initialized.
    AlreadyInitialized = 1,
    /// The published root is not in the pool's root history.
    UnknownRoot = 2,
    /// The nullifier account already exists: the note was spent.
    NullifierAlreadySpent = 3,
    /// The nullifier account is not the PDA for this nullifier.
    NullifierAddressMismatch = 4,
    /// The verifying-key account is not the one the pool pinned.
    WrongVerifyingKey = 5,
    /// The verifier program account is not the Groth16 verifier.
    WrongVerifierProgram = 6,
    /// `forced` is neither 0 nor 1.
    InvalidForcedFlag = 7,
    /// The supply counter would overflow or go negative.
    SupplyOutOfRange = 8,
    /// The commitment tree is full.
    TreeFull = 9,
    /// The Poseidon syscall failed (bad input length or non-canonical input).
    PoseidonFailed = 10,
    /// The vault account is not the pool's vault.
    WrongVault = 11,
    /// The token program account is not the one the pool was created with.
    WrongTokenProgram = 12,
    /// The vault is not an initialized token account of the pool's mint
    /// owned by the vault authority.
    InvalidVaultAccount = 13,
    /// A transfer spends the same note twice.
    DuplicateNullifier = 14,
}

impl From<PoolError> for ProgramError {
    fn from(e: PoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
