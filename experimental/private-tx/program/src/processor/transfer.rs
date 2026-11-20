//! `Transfer`: an in-pool shielded transfer, two notes in, two out.
//!
//! Accounts: `[pool (w), payer (s, w), nullifier PDA 0 (w), nullifier PDA 1
//! (w), system program, verifier program, transfer key]`.
//! Data: `proof (256) ‖ root slot (1) ‖ nf_0 (32) ‖ nf_1 (32) ‖ cm_0 (32) ‖ cm_1 (32)
//! ‖ audit blob (256) ‖ recipient blobs (2 × 83)`.
//!
//! The root is named by its slot in the pool's root history rather than
//! spelled out: the proof binds the root itself, and the 31 bytes saved
//! are what keep a `Transfer` with its compute-budget instruction inside
//! one legacy transaction (1,217 of 1,232 bytes).
//!
//! The proof is `C_transfer` with public inputs `(root, nf_0, nf_1, cm_0,
//! cm_1, audit_hash, sighash)`. The program recomputes `audit_hash` from
//! the audit blob and the pool's audit key, `enc_hash` from the recipient
//! blobs, and `sighash = Poseidon(TSIGHASH, pool, nf_0, nf_1, cm_0, cm_1,
//! audit_hash, enc_hash)`, which both input owners signed inside the proof.
//! So the whole instruction is covered: nothing in it can change without
//! the proof failing. The root must be in the history; the two nullifiers
//! must differ and their PDAs are created; the two commitments are
//! appended. No tokens move and the supply is unchanged: value only
//! changes hands inside the pool.

use {
    super::{
        expect_owned_by, expect_signer, expect_verifier, expect_writable, record_nullifier, take,
        verify_proof,
    },
    crate::{
        error::PoolError,
        state::{audit_hash, blob, enc_hash, transfer_sighash, Pool},
    },
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, payer, nullifier_account_0, nullifier_account_1, system_program, verifier, key] =
        accounts
    else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_writable(pool)?;
    expect_signer(payer)?;
    expect_writable(payer)?;
    expect_writable(nullifier_account_0)?;
    expect_writable(nullifier_account_1)?;
    if system_program.address() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (proof, rest) = take::<PROOF_SIZE>(payload)?;
    let (root_slot, rest) = take::<1>(rest)?;
    let (nf0, rest) = take::<32>(rest)?;
    let (nf1, rest) = take::<32>(rest)?;
    let (cm0, rest) = take::<32>(rest)?;
    let (cm1, rest) = take::<32>(rest)?;
    let (audit_blob, rest) = take::<{ blob::audit_len(2) }>(rest)?;
    let (enc_blobs, rest) = take::<{ 2 * blob::RECIPIENT_LEN }>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if nf0 == nf1 {
        return Err(PoolError::DuplicateNullifier.into());
    }

    let pool_address = *pool.address();
    let (root, audit, sighash) = {
        let mut data = pool.try_borrow_mut()?;
        let p = Pool::from_bytes(&mut data)?;
        expect_verifier(verifier, key, p.transfer_key())?;
        let root = p
            .root_at(root_slot[0] as usize)
            .ok_or(PoolError::UnknownRoot)?;
        let audit = audit_hash(p.audit_pk(), audit_blob, &[])?;
        let eh = enc_hash(enc_blobs)?;
        let sighash = transfer_sighash(
            pool_address.as_array(),
            &[*nf0, *nf1],
            &[*cm0, *cm1],
            &audit,
            &eh,
        )?;
        (root, audit, sighash)
    };

    verify_proof(key, proof, &[root, *nf0, *nf1, *cm0, *cm1, audit, sighash])?;

    record_nullifier(program_id, pool, payer, nullifier_account_0, nf0)?;
    record_nullifier(program_id, pool, payer, nullifier_account_1, nf1)?;

    let mut data = pool.try_borrow_mut()?;
    let mut p = Pool::from_bytes(&mut data)?;
    p.append(cm0)?;
    p.append(cm1)?;
    Ok(())
}
