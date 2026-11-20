//! `Mint`: shield `value` tokens into one note.
//!
//! Accounts: `[pool (w), issuer (s), verifier program, mint key,
//! source token account (w), source owner (s), vault (w), token program]`.
//! Data: `proof (256) ‖ commitment (32) ‖ value (u64 LE) ‖ audit blob (160) ‖ recipient blob (83)`.
//!
//! The proof is `C_mint` with public inputs `(commitment, value,
//! audit_hash)`, where `audit_hash = Poseidon(AUDIT, apk, epk, c_0, c_1, c_2,
//! enc_hash)` is recomputed here from the audit blob, the pool's audit key
//! and the hash of the recipient blob, so both ciphertexts are exactly what
//! the proof was made over. After the verifier accepts it, `value` tokens
//! move from the depositor's account
//! into the vault (the depositor's own transfer authority, so the deposit
//! is theirs to make), the commitment is appended to the tree and `value`
//! added to the supply. The issuer co-signs: who may shield into an
//! institution's pool is the institution's business, not the circuit's.

use {
    super::{
        expect_owned_by, expect_signer, expect_verifier, expect_writable, take, token_transfer,
        verify_proof,
    },
    crate::{
        error::PoolError,
        state::{audit_hash, blob, enc_hash, u64_to_field, Pool},
    },
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::constants::PROOF_SIZE,
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, issuer, verifier, key, source, source_owner, vault, token_program] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_writable(pool)?;
    expect_signer(issuer)?;
    expect_writable(source)?;
    expect_signer(source_owner)?;
    expect_writable(vault)?;

    let (proof, rest) = take::<PROOF_SIZE>(payload)?;
    let (commitment, rest) = take::<32>(rest)?;
    let (value, rest) = take::<8>(rest)?;
    let (audit_blob, rest) = take::<{ blob::audit_len(1) }>(rest)?;
    let (enc_blob, rest) = take::<{ blob::RECIPIENT_LEN }>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let value = u64::from_le_bytes(*value);

    let (pinned_token_program, audit) = {
        let mut data = pool.try_borrow_mut()?;
        let p = Pool::from_bytes(&mut data)?;
        if issuer.address().as_ref() != p.issuer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        expect_verifier(verifier, key, p.mint_key())?;
        if vault.address().as_ref() != p.vault() {
            return Err(PoolError::WrongVault.into());
        }
        let eh = enc_hash(enc_blob)?;
        (
            *p.token_program(),
            audit_hash(p.audit_pk(), audit_blob, &[eh])?,
        )
    };

    verify_proof(key, proof, &[*commitment, u64_to_field(value), audit])?;

    // The deposit backing the note. The token program checks the source's
    // mint against the vault's and the owner's authority.
    token_transfer(
        token_program,
        &pinned_token_program,
        source,
        vault,
        source_owner,
        value,
        &[],
    )?;

    let mut data = pool.try_borrow_mut()?;
    let mut p = Pool::from_bytes(&mut data)?;
    p.append(commitment)?;
    p.add_supply(value)
}
