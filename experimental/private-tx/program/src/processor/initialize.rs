//! `InitializePool`.
//!
//! Accounts: `[pool (s, w), vault, token program]`. Data:
//! `custodian (32) ‖ issuer (32) ‖ mint_key (32) ‖ burn_key (32) ‖ transfer_key (32) ‖ token_mint (32) ‖ audit_pk (64)`.
//!
//! The pool account is created by the client (system `CreateAccount` with
//! this program as owner and [`POOL_ACCOUNT_LEN`] bytes) and must sign here,
//! so only whoever holds its key can initialize it. `mint_key` and
//! `burn_key` are the verifier's content-addressed key accounts for `C_mint`
//! and `C_burn`; pinning them pins the circuits.
//!
//! The vault is created by the client too: an initialized token account of
//! `token_mint` under the classic SPL Token program (Token-2022 is refused,
//! see [`TOKEN_PROGRAM_ID`]), owned by the vault authority PDA
//! `["vault", pool]`. It is checked here and pinned, together with the
//! token program, so later instructions only compare addresses.

use {
    super::{expect_owned_by, expect_signer, expect_writable, take},
    crate::{
        error::PoolError,
        state::{token_account, Pool, POOL_ACCOUNT_LEN, TOKEN_PROGRAM_ID, VAULT_SEED},
    },
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, vault, token_program] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_signer(pool)?;
    expect_writable(pool)?;
    if pool.data_len() != POOL_ACCOUNT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    let (custodian, rest) = take::<32>(payload)?;
    let (issuer, rest) = take::<32>(rest)?;
    let (mint_key, rest) = take::<32>(rest)?;
    let (burn_key, rest) = take::<32>(rest)?;
    let (transfer_key, rest) = take::<32>(rest)?;
    let (token_mint, rest) = take::<32>(rest)?;
    let (audit_pk, rest) = take::<64>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // The vault: an initialized token account of the mint, owned by the
    // vault authority PDA, under the classic SPL Token program only.
    if token_program.address() != &TOKEN_PROGRAM_ID {
        return Err(PoolError::WrongTokenProgram.into());
    }
    if !token_program.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (authority, bump) =
        Address::find_program_address(&[VAULT_SEED, pool.address().as_ref()], program_id);
    {
        expect_owned_by(vault, token_program.address())?;
        let v = vault.try_borrow()?;
        if v.len() < token_account::LEN
            || v[token_account::STATE_OFFSET] != token_account::STATE_INITIALIZED
            || &v[token_account::MINT_OFFSET..token_account::MINT_OFFSET + 32] != token_mint
            || v[token_account::OWNER_OFFSET..token_account::OWNER_OFFSET + 32]
                != *authority.as_array()
        {
            return Err(PoolError::InvalidVaultAccount.into());
        }
    }

    let mut data = pool.try_borrow_mut()?;
    Pool::initialize(
        &mut data,
        &Address::new_from_array(*custodian),
        &Address::new_from_array(*issuer),
        &Address::new_from_array(*mint_key),
        &Address::new_from_array(*burn_key),
        &Address::new_from_array(*transfer_key),
        token_program.address(),
        &Address::new_from_array(*token_mint),
        vault.address(),
        bump,
        audit_pk,
    )?;
    Ok(())
}
