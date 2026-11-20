//! One module per instruction, plus the checks and the verifier CPI they
//! share.
//!
//! Instruction data is `tag ‖ payload`:
//!
//! | tag | instruction                            |
//! | --- | -------------------------------------- |
//! | 0   | [`initialize::process`] `InitializePool` |
//! | 1   | [`mint::process`] `Mint`               |
//! | 2   | [`burn::process`] `Burn`               |
//! | 3   | [`transfer::process`] `Transfer`       |

use {
    crate::{error::PoolError, VERIFIER_ID},
    pinocchio::{
        cpi::{invoke, invoke_signed, Signer},
        error::ProgramError,
        instruction::{InstructionAccount, InstructionView},
        AccountView, Address, ProgramResult,
    },
    solana_groth16_verify::{
        constants::{FR_SIZE, PROOF_SIZE},
        Tag,
    },
};

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod transfer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PoolTag {
    InitializePool = 0,
    Mint = 1,
    Burn = 2,
    Transfer = 3,
}

impl PoolTag {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::InitializePool),
            1 => Some(Self::Mint),
            2 => Some(Self::Burn),
            3 => Some(Self::Transfer),
            _ => None,
        }
    }
}

/// The entrypoint: splits `tag ‖ payload` and dispatches on the tag.
#[inline(never)]
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match PoolTag::from_u8(tag).ok_or(ProgramError::InvalidInstructionData)? {
        PoolTag::InitializePool => initialize::process(program_id, accounts, payload),
        PoolTag::Mint => mint::process(program_id, accounts, payload),
        PoolTag::Burn => burn::process(program_id, accounts, payload),
        PoolTag::Transfer => transfer::process(program_id, accounts, payload),
    }
}

#[inline(always)]
pub(crate) fn expect_signer(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

#[inline(always)]
pub(crate) fn expect_writable(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

#[inline(always)]
pub(crate) fn expect_owned_by(account: &AccountView, owner: &Address) -> Result<(), ProgramError> {
    if !account.owned_by(owner) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// The verifier program account must be the Groth16 verifier, and the key
/// account the one the pool pinned for this circuit.
#[inline(always)]
pub(crate) fn expect_verifier(
    verifier: &AccountView,
    key: &AccountView,
    pinned_key: &[u8; 32],
) -> Result<(), ProgramError> {
    if verifier.address() != &VERIFIER_ID {
        return Err(PoolError::WrongVerifierProgram.into());
    }
    if key.address().as_ref() != pinned_key {
        return Err(PoolError::WrongVerifyingKey.into());
    }
    Ok(())
}

/// Most public inputs any instruction here verifies (`C_transfer`: seven).
pub const MAX_PUBLIC_INPUTS: usize = 7;

/// CPIs `Verify` on the Groth16 verifier: `[3, proof, inputs…]` with the
/// key account as the only account. The verifier rejects a wrong count of
/// inputs, non-canonical scalars and invalid proofs, and the CPI error
/// propagates.
pub(crate) fn verify_proof(
    key: &AccountView,
    proof: &[u8],
    public_inputs: &[[u8; FR_SIZE]],
) -> ProgramResult {
    if proof.len() != PROOF_SIZE || public_inputs.len() > MAX_PUBLIC_INPUTS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut data = [0u8; 1 + PROOF_SIZE + MAX_PUBLIC_INPUTS * FR_SIZE];
    data[0] = Tag::Verify as u8;
    data[1..1 + PROOF_SIZE].copy_from_slice(proof);
    let mut end = 1 + PROOF_SIZE;
    for input in public_inputs {
        data[end..end + FR_SIZE].copy_from_slice(input);
        end += FR_SIZE;
    }
    let accounts = [InstructionAccount::readonly(key.address())];
    let instruction = InstructionView {
        program_id: &VERIFIER_ID,
        accounts: &accounts,
        data: &data[..end],
    };
    invoke::<1, _>(&instruction, &[key])
}

/// SPL Token `Transfer` (instruction 3) of `amount` from `source` to
/// `destination`, authorized by `authority`, through `token_program`, which
/// must be the one the pool pinned. `signers` carries the vault authority's
/// seeds when the pool itself is the authority.
pub(crate) fn token_transfer(
    token_program: &AccountView,
    pinned_token_program: &[u8; 32],
    source: &AccountView,
    destination: &AccountView,
    authority: &AccountView,
    amount: u64,
    signers: &[Signer],
) -> ProgramResult {
    if token_program.address().as_ref() != pinned_token_program {
        return Err(PoolError::WrongTokenProgram.into());
    }
    let mut data = [0u8; 9];
    data[0] = 3;
    data[1..].copy_from_slice(&amount.to_le_bytes());
    let accounts = [
        InstructionAccount::writable(source.address()),
        InstructionAccount::writable(destination.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &data,
    };
    invoke_signed::<3, _>(&instruction, &[source, destination, authority], signers)
}

/// Records a spend: the nullifier account must be the PDA
/// `["nullifier", pool, nullifier]` and must not exist yet; it is created
/// here (rent from `payer`), which is what makes a second spend fail.
pub(crate) fn record_nullifier(
    program_id: &Address,
    pool: &AccountView,
    payer: &AccountView,
    nullifier_account: &mut AccountView,
    nullifier: &[u8; 32],
) -> ProgramResult {
    use {
        crate::state::{NULLIFIER_ACCOUNT_LEN, NULLIFIER_DISCRIMINATOR, NULLIFIER_SEED},
        pinocchio::cpi::Seed,
        pinocchio_system::instructions::CreateAccount,
        solana_groth16_verify::constants::SYSTEM_PROGRAM_ID,
    };
    let (expected, bump) = Address::find_program_address(
        &[NULLIFIER_SEED, pool.address().as_ref(), nullifier],
        program_id,
    );
    if nullifier_account.address() != &expected {
        return Err(PoolError::NullifierAddressMismatch.into());
    }
    if nullifier_account.lamports() != 0
        || nullifier_account.data_len() != 0
        || !nullifier_account.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(PoolError::NullifierAlreadySpent.into());
    }
    let bump = [bump];
    let seeds = [
        Seed::from(NULLIFIER_SEED),
        Seed::from(pool.address().as_ref()),
        Seed::from(nullifier.as_slice()),
        Seed::from(&bump),
    ];
    CreateAccount::with_minimum_balance(
        payer,
        nullifier_account,
        NULLIFIER_ACCOUNT_LEN as u64,
        program_id,
        None,
    )?
    .invoke_signed(&[Signer::from(&seeds)])?;
    nullifier_account.try_borrow_mut()?[0] = NULLIFIER_DISCRIMINATOR;
    Ok(())
}

/// Splits a fixed-size prefix off `payload`.
#[inline(always)]
pub(crate) fn take<const N: usize>(payload: &[u8]) -> Result<(&[u8; N], &[u8]), ProgramError> {
    if payload.len() < N {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (head, rest) = payload.split_at(N);
    Ok((head.try_into().unwrap(), rest))
}
