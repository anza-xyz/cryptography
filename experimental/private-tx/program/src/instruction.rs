//! Client-side instruction builders and PDA derivations. Account orders match
//! the processor modules exactly.

extern crate alloc;

use {
    crate::{
        processor::PoolTag,
        state::{blob, NULLIFIER_SEED, POOL_ACCOUNT_LEN, VAULT_SEED},
        ID, VERIFIER_ID,
    },
    alloc::{vec, vec::Vec},
    pinocchio::Address,
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
    solana_instruction::{AccountMeta, Instruction},
};

/// The nullifier PDA for `nullifier` in `pool`.
pub fn find_nullifier_address(pool: &Address, nullifier: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[NULLIFIER_SEED, pool.as_ref(), nullifier], &ID)
}

/// The vault authority PDA of `pool`: the owner of its vault token account.
pub fn find_vault_authority(pool: &Address) -> (Address, u8) {
    Address::find_program_address(&[VAULT_SEED, pool.as_ref()], &ID)
}

/// Everything a pool is created with besides its own address.
pub struct PoolConfig {
    pub custodian: Address,
    pub issuer: Address,
    pub mint_key: Address,
    pub burn_key: Address,
    pub transfer_key: Address,
    pub token_program: Address,
    pub token_mint: Address,
    pub vault: Address,
    /// The custodian's audit key, `x ‖ y`.
    pub audit_pk: [u8; 64],
}

/// System-program `CreateAccount` for a pool account, followed by
/// `InitializePool`. Submit both in one transaction; `pool` signs both.
/// `lamports` is the rent-exempt minimum for [`POOL_ACCOUNT_LEN`] bytes.
pub fn create_pool(
    payer: &Address,
    pool: &Address,
    lamports: u64,
    config: &PoolConfig,
) -> [Instruction; 2] {
    // SystemInstruction::CreateAccount { lamports, space, owner }, bincode.
    let mut data = Vec::with_capacity(4 + 8 + 8 + 32);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&(POOL_ACCOUNT_LEN as u64).to_le_bytes());
    data.extend_from_slice(ID.as_ref());
    let create = Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*pool, true),
        ],
        data,
    };
    [create, initialize_pool(pool, config)]
}

/// Data `[0, custodian, issuer, mint_key, burn_key, transfer_key, token_mint,
/// audit_pk]`. Accounts: pool (s, w), vault, token program.
pub fn initialize_pool(pool: &Address, config: &PoolConfig) -> Instruction {
    let mut data = Vec::with_capacity(1 + 6 * 32 + 64);
    data.push(PoolTag::InitializePool as u8);
    for a in [
        &config.custodian,
        &config.issuer,
        &config.mint_key,
        &config.burn_key,
        &config.transfer_key,
        &config.token_mint,
    ] {
        data.extend_from_slice(a.as_ref());
    }
    data.extend_from_slice(&config.audit_pk);
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(*pool, true),
            AccountMeta::new_readonly(config.vault, false),
            AccountMeta::new_readonly(config.token_program, false),
        ],
        data,
    }
}

/// Data `[1, proof, commitment, value LE, audit blob, recipient blob]`.
/// Accounts: pool (w), issuer (s), verifier program, mint key, source token
/// account (w), source owner (s), vault (w), token program.
#[allow(clippy::too_many_arguments)]
pub fn mint(
    pool: &Address,
    config: &PoolConfig,
    source: &Address,
    source_owner: &Address,
    proof: &[u8; PROOF_SIZE],
    commitment: &[u8; 32],
    value: u64,
    audit_blob: &[u8; blob::audit_len(1)],
    enc_blob: &[u8; blob::RECIPIENT_LEN],
) -> Instruction {
    let mut data =
        Vec::with_capacity(1 + PROOF_SIZE + 32 + 8 + blob::audit_len(1) + blob::RECIPIENT_LEN);
    data.push(PoolTag::Mint as u8);
    data.extend_from_slice(proof);
    data.extend_from_slice(commitment);
    data.extend_from_slice(&value.to_le_bytes());
    data.extend_from_slice(audit_blob);
    data.extend_from_slice(enc_blob);
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new_readonly(config.issuer, true),
            AccountMeta::new_readonly(VERIFIER_ID, false),
            AccountMeta::new_readonly(config.mint_key, false),
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*source_owner, true),
            AccountMeta::new(config.vault, false),
            AccountMeta::new_readonly(config.token_program, false),
        ],
        data,
    }
}

/// Data `[2, proof, root, nullifier, value LE, forced]`. Accounts: pool (w),
/// payer (s, w), nullifier PDA (w), system program, verifier program, burn
/// key, custodian (s iff forced), vault (w), destination token account (w),
/// vault authority, token program.
#[allow(clippy::too_many_arguments)]
pub fn burn(
    pool: &Address,
    config: &PoolConfig,
    payer: &Address,
    proof: &[u8; PROOF_SIZE],
    root: &[u8; 32],
    nullifier: &[u8; 32],
    value: u64,
    forced: bool,
    destination: &Address,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + PROOF_SIZE + 32 + 32 + 8 + 1);
    data.push(PoolTag::Burn as u8);
    data.extend_from_slice(proof);
    data.extend_from_slice(root);
    data.extend_from_slice(nullifier);
    data.extend_from_slice(&value.to_le_bytes());
    data.push(forced as u8);
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new(find_nullifier_address(pool, nullifier).0, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(VERIFIER_ID, false),
            AccountMeta::new_readonly(config.burn_key, false),
            AccountMeta::new_readonly(config.custodian, forced),
            AccountMeta::new(config.vault, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(find_vault_authority(pool).0, false),
            AccountMeta::new_readonly(config.token_program, false),
        ],
        data,
    }
}

/// Data `[3, proof, root slot, nf_0, nf_1, cm_0, cm_1, audit blob, recipient
/// blobs]`. `root_slot` is the root's position in the pool's history
/// (`Pool::find_root`). Accounts: pool (w), payer (s, w), nullifier PDA 0 (w),
/// nullifier PDA 1 (w), system program, verifier program, transfer key.
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    pool: &Address,
    config: &PoolConfig,
    payer: &Address,
    proof: &[u8; PROOF_SIZE],
    root_slot: u8,
    nullifiers: &[[u8; 32]; 2],
    commitments: &[[u8; 32]; 2],
    audit_blob: &[u8; blob::audit_len(2)],
    enc_blobs: &[u8; 2 * blob::RECIPIENT_LEN],
) -> Instruction {
    let mut data = Vec::with_capacity(
        1 + PROOF_SIZE + 1 + 4 * 32 + blob::audit_len(2) + 2 * blob::RECIPIENT_LEN,
    );
    data.push(PoolTag::Transfer as u8);
    data.extend_from_slice(proof);
    data.push(root_slot);
    data.extend_from_slice(&nullifiers[0]);
    data.extend_from_slice(&nullifiers[1]);
    data.extend_from_slice(&commitments[0]);
    data.extend_from_slice(&commitments[1]);
    data.extend_from_slice(audit_blob);
    data.extend_from_slice(enc_blobs);
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new(find_nullifier_address(pool, &nullifiers[0]).0, false),
            AccountMeta::new(find_nullifier_address(pool, &nullifiers[1]).0, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(VERIFIER_ID, false),
            AccountMeta::new_readonly(config.transfer_key, false),
        ],
        data,
    }
}
