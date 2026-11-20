//! The pool program end to end, under Mollusk with both SBF artifacts and
//! the SPL Token program, replaying the pool fixture's lifecycle: a pool is
//! created over a token mint with the fixture's keys, a vault and the
//! custodian's audit key; five notes are shielded to Alice; Alice pays Bob
//! with change in one `Transfer`; Alice unshields a note, the custodian
//! forfeits another, Bob unshields what he received.
//!
//! Alongside, the indexer rebuilds the pool's history from the very
//! instructions submitted, Alice's and Bob's wallets scan it with their
//! incoming viewing keys and find exactly their notes, the rebuilt Merkle
//! path of a burned leaf equals the one the prover used, and the custodian
//! decrypts the transfer's outputs from the audit blob.
//!
//! Every misuse is rejected: replayed or duplicate nullifier, unknown
//! root, forfeiture without the custodian, swapped destination, tampered
//! ciphertexts, wrong vault or token program, insufficient deposit,
//! tampered public inputs.
//!
//! Skips unless both `solana_groth16_program.so` (`SBF_OUT_DIR`) and
//! `private_tx_pool.so` (`POOL_SBF_OUT_DIR`, default
//! `../program/target/deploy`) exist.

mod sbf;

use {
    mollusk_svm::{
        program::{create_program_account_loader_v3, keyed_account_for_system_program},
        result::{InstructionResult, ProgramResult},
    },
    mollusk_svm_programs_token::token,
    private_tx_e2e::{
        burn_sighash, bytes_from_hex, encrypt, fr_from_hex, hex_bytes,
        indexer::{Indexer, Wallet},
        PoolBurn, PoolFixture,
    },
    private_tx_pool::{
        error::PoolError,
        instruction::{self as pool_ix, PoolConfig},
        state::{
            blob, token_account, Pool, NULLIFIER_ACCOUNT_LEN, NULLIFIER_DISCRIMINATOR,
            POOL_ACCOUNT_LEN, ROOTS_OFFSET,
        },
    },
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
    solana_instruction::Instruction,
    solana_program_error::ProgramError,
};

const FIXTURE: &str = "pool";

/// Account state carried from one instruction to the next, and the
/// indexer watching what goes through.
struct World {
    h: sbf::Harness,
    accounts: Vec<(Address, Account)>,
    indexer: Indexer,
}

impl World {
    fn get(&self, a: &Address) -> &Account {
        &self
            .accounts
            .iter()
            .find(|(k, _)| k == a)
            .expect("account")
            .1
    }

    /// Runs one instruction against the current state and, on success,
    /// adopts the resulting accounts and lets the indexer see it. Accounts
    /// not seen before start empty, except the programs.
    fn run(&mut self, ix: &Instruction) -> InstructionResult {
        for m in &ix.accounts {
            if self.accounts.iter().any(|(k, _)| *k == m.pubkey) {
                continue;
            }
            let account = if m.pubkey == private_tx_pool::VERIFIER_ID {
                create_program_account_loader_v3(&m.pubkey)
            } else if m.pubkey == token::ID {
                token::account()
            } else {
                Account::default()
            };
            self.accounts.push((m.pubkey, account));
        }
        let r = self.h.mollusk.process_instruction(ix, &self.accounts);
        if r.program_result.is_ok() {
            self.accounts = r.resulting_accounts.clone();
            self.indexer.observe(ix);
        }
        r
    }
}

fn funded() -> Account {
    Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: SYSTEM_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// An initialized SPL Token account (classic 165-byte layout).
fn token_account_of(mint: &Address, owner: &Address, amount: u64) -> Account {
    let mut data = vec![0u8; token_account::LEN];
    data[token_account::MINT_OFFSET..token_account::MINT_OFFSET + 32]
        .copy_from_slice(mint.as_array());
    data[token_account::OWNER_OFFSET..token_account::OWNER_OFFSET + 32]
        .copy_from_slice(owner.as_array());
    data[token_account::AMOUNT_OFFSET..token_account::AMOUNT_OFFSET + 8]
        .copy_from_slice(&amount.to_le_bytes());
    data[token_account::STATE_OFFSET] = token_account::STATE_INITIALIZED;
    Account {
        lamports: 10_000_000,
        data,
        owner: token::ID,
        executable: false,
        rent_epoch: 0,
    }
}

fn token_amount(a: &Account) -> u64 {
    u64::from_le_bytes(
        a.data[token_account::AMOUNT_OFFSET..token_account::AMOUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

/// SPL Token's `InsufficientFunds`.
const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;

fn proof_bytes(p: &[u8]) -> &[u8; PROOF_SIZE] {
    p.try_into().unwrap()
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().expect("length")
}

fn assert_pool_error(r: &InstructionResult, e: PoolError) {
    sbf::assert_custom_error(r, e as u32);
}

fn assert_missing_signature(r: &InstructionResult) {
    assert_eq!(
        r.program_result,
        ProgramResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

/// Reads the pool account through the program's own view.
fn with_pool<T>(w: &World, pool: &Address, f: impl FnOnce(&Pool) -> T) -> T {
    let mut data = w.get(pool).data.clone();
    f(&Pool::from_bytes(&mut data).expect("pool account"))
}

struct Setup {
    w: World,
    f: PoolFixture,
    pool: Address,
    config: PoolConfig,
    payer: Address,
    /// The depositor's token account, owned by `payer`, funded with the
    /// fixture's total.
    depositor: Address,
    /// The destination token account the fixture's burns were signed for.
    destination: Address,
    alice: Wallet,
    bob: Wallet,
}

impl Setup {
    fn vault_amount(&self) -> u64 {
        token_amount(self.w.get(&self.config.vault))
    }
    fn shielded(&self) -> u64 {
        self.f.mints.iter().map(|m| m.note.value).sum()
    }
}

/// Registers the three keys, sets up the token accounts, creates and
/// initializes a pool.
fn setup() -> Option<Setup> {
    let h = sbf::Harness::with_pool()?;
    let f = PoolFixture::load(FIXTURE);
    let mint_key = h.register(&f.mint_proof(FIXTURE, 0).key);
    let burn_key = h.register(&f.burn_proof(FIXTURE, &f.burns[0]).key);
    let transfer_key = h.register(&f.transfer_proof(FIXTURE).key);

    let payer = Address::new_unique();
    let issuer = Address::new_unique();
    let custodian = Address::new_unique();
    // The fixture's burns were signed for this pool address and this
    // destination token account.
    let pool = Address::new_from_array(bytes_from_hex(&f.pool));
    let destination = Address::new_from_array(bytes_from_hex(&f.destination));
    let token_mint = Address::new_unique();
    let vault = Address::new_unique();
    let depositor = Address::new_unique();
    let recipient = Address::new_unique();
    let total: u64 = f.mints.iter().map(|m| m.note.value).sum();
    let config = PoolConfig {
        custodian,
        issuer,
        mint_key: mint_key.0,
        burn_key: burn_key.0,
        transfer_key: transfer_key.0,
        token_program: token::ID,
        token_mint,
        vault,
        audit_pk: f.custodian.audit_pk_bytes(),
    };
    let vault_authority = pool_ix::find_vault_authority(&pool).0;
    let mut w = World {
        accounts: vec![
            (payer, funded()),
            (issuer, funded()),
            (custodian, funded()),
            (pool, Account::default()),
            mint_key.clone(),
            burn_key.clone(),
            transfer_key.clone(),
            keyed_account_for_system_program(),
            token::keyed_account(),
            (vault, token_account_of(&token_mint, &vault_authority, 0)),
            (depositor, token_account_of(&token_mint, &payer, total)),
            (destination, token_account_of(&token_mint, &recipient, 0)),
        ],
        h,
        indexer: Indexer::default(),
    };

    let lamports = w.h.rent_exempt(POOL_ACCOUNT_LEN);
    let [create, init] = pool_ix::create_pool(&payer, &pool, lamports, &config);
    sbf::assert_success(&w.run(&create));

    // A vault that is not owned by the vault authority is refused.
    let mut bad = init.clone();
    bad.accounts[1].pubkey = depositor;
    assert_pool_error(&w.run(&bad), PoolError::InvalidVaultAccount);

    let r = w.run(&init);
    sbf::assert_success(&r);
    println!("InitializePool: {} CUs", r.compute_units_consumed);

    // A second initialization of the same account is refused.
    assert_pool_error(&w.run(&init), PoolError::AlreadyInitialized);

    let alice = f.wallets["alice"].wallet();
    let bob = f.wallets["bob"].wallet();
    Some(Setup {
        w,
        f,
        pool,
        config,
        payer,
        depositor,
        destination,
        alice,
        bob,
    })
}

fn mint_ix(s: &Setup, i: usize) -> Instruction {
    let g = s.f.mint_proof(FIXTURE, i);
    let m = &s.f.mints[i];
    assert_eq!(g.public_inputs[0], m.note.commitment_bytes());
    assert_eq!(g.public_inputs[2], bytes_from_hex(&m.audit_hash));
    pool_ix::mint(
        &s.pool,
        &s.config,
        &s.depositor,
        &s.payer,
        proof_bytes(&g.proof.0),
        &m.note.commitment_bytes(),
        m.note.value,
        &arr(&hex_bytes(&m.audit_blob)),
        &arr(&hex_bytes(&m.enc_blob)),
    )
}

/// Shields every note of the fixture, checking the tree, the supply and
/// the vault as it goes.
fn shield_all(s: &mut Setup) {
    let empty_root = with_pool(&s.w, &s.pool, |p| *p.current_root());
    assert_eq!(
        empty_root,
        private_tx_e2e::merkle_root(&[], s.f.depth),
        "empty root on-chain disagrees with light-poseidon"
    );

    let total = s.shielded();
    let mut expected_supply = 0u64;
    for i in 0..s.f.mints.len() {
        let ix = mint_ix(s, i);
        let r = s.w.run(&ix);
        sbf::assert_success(&r);
        println!("Mint #{i}: {} CUs", r.compute_units_consumed);
        expected_supply += s.f.mints[i].note.value;
        with_pool(&s.w, &s.pool, |p| {
            assert_eq!(p.next_index(), i as u64 + 1);
            assert_eq!(p.supply(), expected_supply);
        });
        assert_eq!(s.vault_amount(), expected_supply);
        assert_eq!(token_amount(s.w.get(&s.depositor)), total - expected_supply);
    }
    let root = with_pool(&s.w, &s.pool, |p| *p.current_root());
    assert_eq!(
        root,
        bytes_from_hex(&s.f.transfer.root),
        "root after the shields is the one the transfer was proved against"
    );
    assert_eq!(
        root,
        s.w.indexer.root(s.f.depth),
        "the indexer's tree disagrees with the chain"
    );
}

fn transfer_ix(s: &Setup) -> Instruction {
    let g = s.f.transfer_proof(FIXTURE);
    let t = &s.f.transfer;
    let nullifiers = [
        bytes_from_hex(&t.nullifiers[0]),
        bytes_from_hex(&t.nullifiers[1]),
    ];
    let commitments = [
        bytes_from_hex(&t.commitments[0]),
        bytes_from_hex(&t.commitments[1]),
    ];
    let audit_blob = hex_bytes(&t.audit_blob);
    let enc_blobs: Vec<u8> = t.enc_blobs.iter().flat_map(|b| hex_bytes(b)).collect();
    // The fixture's hashes are what the program will recompute.
    let enc_hash = encrypt::enc_hash(&enc_blobs);
    assert_eq!(enc_hash, bytes_from_hex(&t.enc_hash));
    let audit_hash = encrypt::audit_hash(&s.f.custodian.audit_pk(), &audit_blob, &[]);
    assert_eq!(audit_hash, bytes_from_hex(&t.audit_hash));
    let sighash = encrypt::transfer_sighash(
        s.pool.as_array(),
        &nullifiers,
        &commitments,
        &audit_hash,
        &enc_hash,
    );
    assert_eq!(sighash, bytes_from_hex(&t.sighash));
    assert_eq!(
        g.public_inputs,
        vec![
            bytes_from_hex(&t.root),
            nullifiers[0],
            nullifiers[1],
            commitments[0],
            commitments[1],
            audit_hash,
            sighash
        ],
        "transfer public inputs"
    );
    let slot = with_pool(&s.w, &s.pool, |p| p.find_root(&bytes_from_hex(&t.root)))
        .expect("the transfer's root is in the pool's history");
    pool_ix::transfer(
        &s.pool,
        &s.config,
        &s.payer,
        proof_bytes(&g.proof.0),
        slot as u8,
        &nullifiers,
        &commitments,
        &arr(&audit_blob),
        &arr(&enc_blobs),
    )
}

fn burn_ix(s: &Setup, b: &PoolBurn, custodian_signs: bool) -> Instruction {
    let g = s.f.burn_proof(FIXTURE, b);
    let note = s.f.note_at(b.index);
    let nullifier = bytes_from_hex(&b.nullifier);
    let destination = Address::new_from_array(bytes_from_hex(&b.destination));
    assert_eq!(destination, s.destination, "one destination per fixture");
    assert_eq!(g.public_inputs[0], bytes_from_hex(&s.f.root));
    assert_eq!(g.public_inputs[1], nullifier);
    assert_eq!(
        nullifier,
        private_tx_e2e::nullifier(&bytes_from_hex(&b.nk), &note.commitment_bytes(), b.index),
        "fixture nullifier is not Poseidon(nk, cm, index)"
    );
    assert_eq!(
        g.public_inputs[4],
        burn_sighash(
            s.pool.as_array(),
            destination.as_array(),
            &nullifier,
            note.value
        ),
        "fixture sighash is not Poseidon(pool, destination, nullifier, value)"
    );
    let mut ix = pool_ix::burn(
        &s.pool,
        &s.config,
        &s.payer,
        proof_bytes(&g.proof.0),
        &bytes_from_hex(&s.f.root),
        &nullifier,
        note.value,
        b.forced,
        &destination,
    );
    ix.accounts[6].is_signer = custodian_signs;
    ix
}

fn find_burn(s: &Setup, name: &str) -> PoolBurn {
    s.f.burns
        .iter()
        .find(|b| b.name == name)
        .expect("burn in fixture")
        .clone()
}

#[test]
fn lifecycle() {
    let Some(mut s) = setup() else { return };
    shield_all(&mut s);
    let shielded = s.shielded();

    // Alice's wallet scans the indexed history and finds her five notes;
    // Bob finds nothing yet.
    let alices = s.alice.scan(&s.w.indexer);
    assert_eq!(alices.len(), s.f.mints.len());
    for (i, o) in alices.iter().enumerate() {
        assert_eq!(o.index, i as u64);
        assert_eq!(o.note.value, s.f.mints[i].note.value);
        assert_eq!(o.note.commitment(), s.f.mints[i].note.commitment_bytes());
    }
    assert!(s.bob.scan(&s.w.indexer).is_empty());

    // The transfer: Alice spends notes 0 and 1, pays Bob, keeps the change.
    let ix = transfer_ix(&s);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Transfer: {} CUs", r.compute_units_consumed);
    with_pool(&s.w, &s.pool, |p| {
        assert_eq!(p.next_index(), s.f.mints.len() as u64 + 2);
        assert_eq!(p.supply(), shielded, "a transfer moves no value in or out");
    });
    assert_eq!(s.vault_amount(), shielded);
    let root = with_pool(&s.w, &s.pool, |p| *p.current_root());
    assert_eq!(root, bytes_from_hex(&s.f.root), "pool.json final root");
    assert_eq!(root, s.f.poseidon_root());
    assert_eq!(root, s.w.indexer.root(s.f.depth));
    for nf in &s.f.transfer.nullifiers {
        let acc =
            s.w.get(&pool_ix::find_nullifier_address(&s.pool, &bytes_from_hex(nf)).0);
        assert_eq!(
            acc.data,
            vec![NULLIFIER_DISCRIMINATOR; NULLIFIER_ACCOUNT_LEN]
        );
    }

    // Wallets after the transfer: Alice has her three untouched notes and
    // the change, Bob his payment, and neither sees the other's.
    let t = &s.f.transfer;
    let alices = s.alice.scan(&s.w.indexer);
    let bobs = s.bob.scan(&s.w.indexer);
    assert_eq!(
        alices.iter().map(|o| o.index).collect::<Vec<_>>(),
        vec![2, 3, 4, 6],
        "alice's unspent notes"
    );
    assert_eq!(bobs.len(), 1);
    assert_eq!(bobs[0].index, 5);
    assert_eq!(bobs[0].note.value, t.outputs[0].value);
    assert_eq!(bobs[0].note.commitment(), bytes_from_hex(&t.commitments[0]));
    assert_eq!(alices[3].note.value, t.outputs[1].value);
    assert_eq!(
        t.outputs[0].value + t.outputs[1].value,
        s.f.mints[0].note.value + s.f.mints[1].note.value,
        "conservation"
    );

    // The custodian reads both outputs from the audit blob.
    let seen = encrypt::audit_decrypt(
        &fr_from_hex(&s.f.custodian.audit_sk),
        &hex_bytes(&t.audit_blob),
    )
    .expect("audit decrypt");
    assert_eq!(seen.len(), 2);
    for (i, n) in seen.iter().enumerate() {
        assert_eq!(n.value, t.outputs[i].value);
        assert_eq!(n.commitment(), bytes_from_hex(&t.commitments[i]));
        assert_eq!(n.d, arr::<11>(&bytes_from_hex(&t.outputs[i].d)[21..]));
    }

    // The indexer rebuilds the Merkle path the prover used for Alice's
    // unshield.
    let unshield = find_burn(&s, "unshield");
    let path = s.w.indexer.path(s.f.depth, unshield.index);
    assert_eq!(
        path,
        unshield
            .siblings
            .iter()
            .map(|h| bytes_from_hex(h))
            .collect::<Vec<_>>(),
        "rebuilt Merkle path"
    );

    // Alice unshields note 2: the vault pays the destination.
    let ix = burn_ix(&s, &unshield, false);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Burn (unshield): {} CUs", r.compute_units_consumed);
    let v2 = s.f.note_at(unshield.index).value;
    assert_eq!(token_amount(s.w.get(&s.destination)), v2);
    assert_eq!(s.vault_amount(), shielded - v2);
    // Replaying it: the nullifier account exists.
    assert_pool_error(&s.w.run(&ix), PoolError::NullifierAlreadySpent);
    // And Alice's wallet no longer lists the note.
    assert_eq!(
        s.alice
            .scan(&s.w.indexer)
            .iter()
            .map(|o| o.index)
            .collect::<Vec<_>>(),
        vec![3, 4, 6]
    );

    // The custodian forfeits note 4, which it read from the shield's audit
    // blob, with Alice's registered full viewing key. It needs to sign.
    let forfeit = find_burn(&s, "forfeit");
    assert_missing_signature(&s.w.run(&burn_ix(&s, &forfeit, false)));
    let mut ix = burn_ix(&s, &forfeit, true);
    ix.accounts[6].pubkey = s.config.issuer;
    assert_missing_signature(&s.w.run(&ix));
    let ix = burn_ix(&s, &forfeit, true);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Burn (forfeit): {} CUs", r.compute_units_consumed);
    let v4 = s.f.note_at(forfeit.index).value;
    assert_eq!(s.vault_amount(), shielded - v2 - v4);

    // Bob unshields what Alice paid him.
    let bob_burn = find_burn(&s, "unshield-bob");
    assert_eq!(bob_burn.index, bobs[0].index);
    let ix = burn_ix(&s, &bob_burn, false);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Burn (unshield, bob): {} CUs", r.compute_units_consumed);
    let vb = t.outputs[0].value;
    assert_eq!(s.vault_amount(), shielded - v2 - v4 - vb);
    assert_eq!(token_amount(s.w.get(&s.destination)), v2 + v4 + vb);
    with_pool(&s.w, &s.pool, |p| {
        assert_eq!(p.supply(), shielded - v2 - v4 - vb)
    });
    assert!(s.bob.scan(&s.w.indexer).is_empty());
}

#[test]
fn mint_rejects_wrong_issuer_key_vault_and_tampered_inputs() {
    let Some(mut s) = setup() else { return };

    // Not the issuer.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[1].pubkey = s.config.custodian;
    assert_missing_signature(&s.w.run(&ix));

    // The burn key is not the mint key.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[3].pubkey = s.config.burn_key;
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVerifyingKey);

    // Depositing into some other token account than the pool's vault.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[6].pubkey = s.destination;
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVault);

    // Not the pool's token program.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[7].pubkey = Address::new_unique();
    assert_pool_error(&s.w.run(&ix), PoolError::WrongTokenProgram);

    // A depositor who cannot cover the note: the token program's refusal
    // propagates through the CPI, after the proof verified.
    let poor = Address::new_unique();
    s.w.accounts
        .push((poor, token_account_of(&s.config.token_mint, &s.payer, 0)));
    let mut ix = mint_ix(&s, 0);
    ix.accounts[4].pubkey = poor;
    assert_eq!(
        s.w.run(&ix).program_result,
        ProgramResult::Failure(ProgramError::Custom(TOKEN_INSUFFICIENT_FUNDS))
    );

    // Another value than the proof opens to: the verifier's rejection
    // propagates through the CPI.
    let value_off = 1 + PROOF_SIZE + 32;
    let mut ix = mint_ix(&s, 0);
    ix.data[value_off] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // A tampered audit ciphertext, or recipient blob: the hashes change.
    let mut ix = mint_ix(&s, 0);
    ix.data[value_off + 8 + 64 + 5] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);
    let mut ix = mint_ix(&s, 0);
    let n = ix.data.len();
    ix.data[n - 1] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Nothing was appended, nothing deposited.
    with_pool(&s.w, &s.pool, |p| {
        assert_eq!(p.next_index(), 0);
        assert_eq!(p.supply(), 0);
    });
    assert_eq!(s.vault_amount(), 0);
    assert!(s.w.indexer.leaves.is_empty());
}

#[test]
fn transfer_rejects_tampering_and_double_spends() {
    let Some(mut s) = setup() else { return };
    shield_all(&mut s);
    let root_off = 1 + PROOF_SIZE; // the root's history slot, one byte
    let nf_off = root_off + 1;
    let audit_off = nf_off + 4 * 32;
    let enc_off = audit_off + blob::audit_len(2);

    // An empty history slot, or one past the history.
    let mut ix = transfer_ix(&s);
    ix.data[root_off] = 63;
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);
    let mut ix = transfer_ix(&s);
    ix.data[root_off] = 64;
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);
    // A root the pool did have (before the last shield), not the proof's.
    let mut ix = transfer_ix(&s);
    ix.data[root_off] -= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // The same nullifier twice (one note spent as both inputs).
    let mut ix = transfer_ix(&s);
    let nf0: Vec<u8> = ix.data[nf_off..nf_off + 32].to_vec();
    ix.data[nf_off + 32..nf_off + 64].copy_from_slice(&nf0);
    ix.accounts[3].pubkey = ix.accounts[2].pubkey;
    assert_pool_error(&s.w.run(&ix), PoolError::DuplicateNullifier);

    // A tampered recipient blob: the sighash the owners signed changes.
    let mut ix = transfer_ix(&s);
    ix.data[enc_off + 40] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // A tampered audit ciphertext.
    let mut ix = transfer_ix(&s);
    ix.data[audit_off + 64 + 3] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Another output commitment, or nullifier (with its PDA to match).
    let mut ix = transfer_ix(&s);
    ix.data[nf_off + 64 + 31] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);
    let mut ix = transfer_ix(&s);
    ix.data[nf_off + 31] ^= 1;
    let nf: [u8; 32] = ix.data[nf_off..nf_off + 32].try_into().unwrap();
    ix.accounts[2].pubkey = pool_ix::find_nullifier_address(&s.pool, &nf).0;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // The wrong key account.
    let mut ix = transfer_ix(&s);
    ix.accounts[6].pubkey = s.config.burn_key;
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVerifyingKey);

    // The real one goes through once...
    let ix = transfer_ix(&s);
    sbf::assert_success(&s.w.run(&ix));
    // ...and not twice.
    assert_pool_error(&s.w.run(&ix), PoolError::NullifierAlreadySpent);

    // After it, a burn of a spent note is refused too: Alice's note 0 was
    // an input, and its nullifier exists.
    let spent = s.alice.scan(&s.w.indexer);
    assert!(spent.iter().all(|o| o.index != 0 && o.index != 1));
}

#[test]
fn burn_rejects_unknown_root_and_tampered_inputs() {
    let Some(mut s) = setup() else { return };
    shield_all(&mut s);
    sbf::assert_success(&s.w.run(&transfer_ix(&s)));
    let unshield = find_burn(&s, "unshield");
    let root_off = 1 + PROOF_SIZE;

    // A root the pool never had.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off + 31] ^= 1;
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);

    // The zero word is never a root, even though unused history slots are zero.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off..root_off + 32].fill(0);
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);

    // A root the pool did have (the empty tree's, first in the history), but
    // not the one the proof was made for.
    let mut ix = burn_ix(&s, &unshield, false);
    let old_root = s.w.get(&s.pool).data[ROOTS_OFFSET..ROOTS_OFFSET + 32].to_vec();
    assert_ne!(old_root, bytes_from_hex(&s.f.root));
    ix.data[root_off..root_off + 32].copy_from_slice(&old_root);
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Another nullifier, value or flag than the proof opens to.
    for (what, off) in [
        ("nullifier", root_off + 32 + 31),
        ("value", root_off + 64),
        ("forced", root_off + 72),
    ] {
        let mut ix = burn_ix(&s, &unshield, false);
        ix.data[off] ^= 1;
        if what == "nullifier" {
            let nf: [u8; 32] = ix.data[root_off + 32..root_off + 64].try_into().unwrap();
            ix.accounts[2].pubkey = pool_ix::find_nullifier_address(&s.pool, &nf).0;
        }
        if what == "forced" {
            ix.accounts[6].is_signer = true;
        }
        let r = s.w.run(&ix);
        sbf::assert_custom_error(&r, sbf::code::PROOF_INVALID);
        assert!(r.program_result.is_err(), "wrong {what} accepted");
    }

    // The mempool replay: same proof, another destination token account.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[8].pubkey = s.depositor;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Paying out of some other token account than the vault.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[7].pubkey = s.depositor;
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVault);

    // A vault authority that is not the pool's PDA.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[9].pubkey = Address::new_unique();
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVault);

    // Not the pool's token program.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[10].pubkey = Address::new_unique();
    assert_pool_error(&s.w.run(&ix), PoolError::WrongTokenProgram);

    // The nullifier account must be the PDA for the published nullifier.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[2].pubkey = Address::new_unique();
    assert_pool_error(&s.w.run(&ix), PoolError::NullifierAddressMismatch);

    // forced ∉ {0, 1}.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off + 72] = 2;
    assert_pool_error(&s.w.run(&ix), PoolError::InvalidForcedFlag);

    // Nothing changed.
    let total = s.shielded();
    with_pool(&s.w, &s.pool, |p| assert_eq!(p.supply(), total));
    assert_eq!(s.vault_amount(), total);
    assert_eq!(token_amount(s.w.get(&s.destination)), 0);
}
