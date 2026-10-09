//! Minimal Mollusk harness for the verifier program: register a key through
//! the documented `create_account ‖ InitializeStaging ‖ Write… ‖ Publish`
//! flow, then `Verify`. Skips (returns `None`) unless `SBF_OUT_DIR` holds
//! `solana_groth16_program.so`; `make verifier-sbf` in the parent directory
//! builds it.

#![allow(dead_code)]

use {
    groth16_convert::OnChainKey,
    mollusk_svm::{
        program::keyed_account_for_system_program,
        result::{InstructionResult, ProgramResult},
        Mollusk,
    },
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::{
        constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
        instruction::{self as ix, find_key_address},
        state::{key_account_len, staging_account_len},
    },
    solana_program_error::ProgramError,
};

pub const PROGRAM_SO: &str = "solana_groth16_program";

/// Custom error codes of the verifier program.
pub mod code {
    pub const PUBLIC_INPUT_COUNT_MISMATCH: u32 = 3;
    pub const NON_CANONICAL_SCALAR: u32 = 4;
    pub const INVALID_POINT: u32 = 5;
    pub const PROOF_INVALID: u32 = 6;
}

pub struct Harness {
    pub mollusk: Mollusk,
    pub program_id: Address,
}

impl Harness {
    pub fn new() -> Option<Self> {
        let out_dir = match std::env::var_os("SBF_OUT_DIR") {
            Some(d) => std::path::PathBuf::from(d),
            None => {
                eprintln!("skipping SBF test: set SBF_OUT_DIR (see `make verifier-sbf`)");
                return None;
            }
        };
        let so = out_dir.join(format!("{PROGRAM_SO}.so"));
        if !so.exists() {
            eprintln!(
                "skipping SBF test: {} not found (see `make verifier-sbf`)",
                so.display()
            );
            return None;
        }
        let program_id = ix::ID;
        let mut mollusk = Mollusk::default();
        mollusk.add_program(&program_id, PROGRAM_SO);
        Some(Self {
            mollusk,
            program_id,
        })
    }

    fn rent_exempt(&self, data_len: usize) -> u64 {
        self.mollusk.sysvars.rent.minimum_balance(data_len)
    }

    /// Registers `key` from a fresh funded authority and returns the
    /// published, content-addressed key account.
    pub fn register(&self, key: &OnChainKey) -> (Address, Account) {
        let n = key.num_public_inputs();
        let authority = Address::new_unique();
        let staging = Address::new_unique();
        let key_pda = find_key_address(&self.program_id, &key.hash()).0;

        let mut instructions = ix::create_staging(
            &self.program_id,
            &authority,
            &authority,
            &staging,
            n as u16,
            self.rent_exempt(staging_account_len(n)),
        )
        .to_vec();
        instructions.extend(ix::write_body(
            &self.program_id,
            &authority,
            &staging,
            key.body(),
            800,
        ));
        instructions.push(ix::publish(
            &self.program_id,
            &authority,
            &authority,
            &staging,
            &key_pda,
        ));

        let accounts = vec![
            (
                authority,
                Account {
                    lamports: 10_000_000_000,
                    data: vec![],
                    owner: SYSTEM_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            ),
            (staging, Account::default()),
            (key_pda, Account::default()),
            keyed_account_for_system_program(),
        ];
        let result = self
            .mollusk
            .process_instruction_chain(&instructions, &accounts);
        assert_success(&result);
        let account = result
            .resulting_accounts
            .iter()
            .find(|(a, _)| *a == key_pda)
            .map(|(_, acc)| acc.clone())
            .expect("key account in result");
        assert_eq!(account.owner, self.program_id);
        assert_eq!(account.data.len(), key_account_len(n));
        (key_pda, account)
    }

    pub fn verify(
        &self,
        key: &(Address, Account),
        proof: &[u8; PROOF_SIZE],
        public_inputs: &[[u8; 32]],
    ) -> InstructionResult {
        let instruction = ix::verify(&self.program_id, &key.0, proof, public_inputs);
        self.mollusk
            .process_instruction(&instruction, std::slice::from_ref(key))
    }
}

pub fn assert_success(result: &InstructionResult) {
    assert!(
        result.program_result.is_ok(),
        "expected success, got {:?}",
        result.program_result
    );
}

pub fn assert_custom_error(result: &InstructionResult, code: u32) {
    let expected = ProgramError::Custom(code);
    match &result.program_result {
        ProgramResult::Failure(e) if *e == expected => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}
