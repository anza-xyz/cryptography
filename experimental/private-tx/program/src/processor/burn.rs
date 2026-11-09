//! `Burn`: remove one note with a public amount, as its owner (unshield) or
//! as the custodian (forfeiture).
//!
//! Accounts: `[pool (w), payer (s, w), nullifier PDA (w), system program,
//! verifier program, burn key, custodian, vault (w), destination token
//! account (w), vault authority PDA, token program]`.
//! Data: `proof (256) ‖ root (32) ‖ nullifier (32) ‖ value (u64 LE) ‖ forced (1)`.
//!
//! The proof is `C_burn` with public inputs `(root, nullifier, value,
//! forced, sighash)`, where `sighash = Poseidon(SIGHASH, pool,
//! destination, nullifier, value)` is recomputed here with the destination
//! token account's address. For an unshield the circuit checked the
//! owner's signature over that sighash, so the proof is only good for this
//! pool and this destination: a copy that names another token account
//! fails verification. The root must be in the pool's history; the
//! nullifier PDA (`["nullifier", pool, nullifier]`) must not exist yet and
//! is created here, which is what records the spend; `forced = 1`
//! additionally needs the custodian's signature, since the circuit then
//! checks no owner signature. Then the vault pays `value` to the
//! destination, signed by the vault authority PDA, and `value` leaves the
//! supply.

use {
    super::{
        expect_owned_by, expect_signer, expect_verifier, expect_writable, record_nullifier, take,
        token_transfer, verify_proof,
    },
    crate::{
        error::PoolError,
        state::{burn_sighash, u64_to_field, Pool, VAULT_SEED},
    },
    pinocchio::{
        cpi::{Seed, Signer},
        error::ProgramError,
        AccountView, Address, ProgramResult,
    },
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, payer, nullifier_account, system_program, verifier, key, custodian, vault, destination, vault_authority, token_program] =
        accounts
    else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_writable(pool)?;
    expect_signer(payer)?;
    expect_writable(payer)?;
    expect_writable(nullifier_account)?;
    expect_writable(vault)?;
    expect_writable(destination)?;
    if system_program.address() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (proof, rest) = take::<PROOF_SIZE>(payload)?;
    let (root, rest) = take::<32>(rest)?;
    let (nullifier, rest) = take::<32>(rest)?;
    let (value, rest) = take::<8>(rest)?;
    let (forced, rest) = take::<1>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let value = u64::from_le_bytes(*value);
    let forced = match forced[0] {
        0 => false,
        1 => true,
        _ => return Err(PoolError::InvalidForcedFlag.into()),
    };

    let (pinned_token_program, vault_bump) = {
        let mut data = pool.try_borrow_mut()?;
        let p = Pool::from_bytes(&mut data)?;
        expect_verifier(verifier, key, p.burn_key())?;
        if vault.address().as_ref() != p.vault() {
            return Err(PoolError::WrongVault.into());
        }
        if forced {
            if custodian.address().as_ref() != p.custodian() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            expect_signer(custodian)?;
        }
        if !p.knows_root(root) {
            return Err(PoolError::UnknownRoot.into());
        }
        (*p.token_program(), p.vault_bump())
    };

    let sighash = burn_sighash(
        pool.address().as_array(),
        destination.address().as_array(),
        nullifier,
        value,
    )?;
    verify_proof(
        key,
        proof,
        &[
            *root,
            *nullifier,
            u64_to_field(value),
            u64_to_field(forced as u64),
            sighash,
        ],
    )?;

    // Record the spend: creating the PDA is what makes a second burn fail.
    record_nullifier(program_id, pool, payer, nullifier_account, nullifier)?;

    // Release the backing to the destination the proof was made for.
    let vault_bump = [vault_bump];
    let vault_seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(pool.address().as_ref()),
        Seed::from(&vault_bump),
    ];
    let expected_authority = Address::create_program_address(
        &[VAULT_SEED, pool.address().as_ref(), &vault_bump],
        program_id,
    )?;
    if vault_authority.address() != &expected_authority {
        return Err(PoolError::WrongVault.into());
    }
    token_transfer(
        token_program,
        &pinned_token_program,
        vault,
        destination,
        vault_authority,
        value,
        &[Signer::from(&vault_seeds)],
    )?;

    let mut data = pool.try_borrow_mut()?;
    let mut p = Pool::from_bytes(&mut data)?;
    p.sub_supply(value)
}
