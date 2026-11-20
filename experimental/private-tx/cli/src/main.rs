//! `privtx-cli`: the live-cluster side of the demo.
//!
//! Everything that touches a validator lives here: registering verifying
//! keys with the Groth16 verifier program, creating the token accounts and
//! the pool, turning the proofs `privtx` writes into `Mint`, `Transfer`
//! and `Burn` transactions, and indexing a pool from its transaction
//! history for the wallets to scan. Proving stays in Go.

use {
    anyhow::{anyhow, bail, Context, Result},
    clap::{Parser, Subcommand},
    groth16_convert::{arkworks, gnark, OnChainKey},
    private_tx_e2e::indexer::Indexer,
    private_tx_pool::{
        instruction::{self as pool_ix, PoolConfig},
        state::{blob, token_account, Pool, POOL_ACCOUNT_LEN},
    },
    solana_address::Address,
    solana_commitment_config::CommitmentConfig,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_groth16_verify::{
        constants::PROOF_SIZE,
        instruction::{self as verifier_ix, find_key_address},
        state::staging_account_len,
    },
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::{read_keypair_file, Keypair},
    solana_rpc_client::rpc_client::GetConfirmedSignaturesForAddress2Config,
    solana_rpc_client::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcTransactionConfig,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::Transaction,
    solana_transaction_status_client_types::UiTransactionEncoding,
    std::{path::PathBuf, str::FromStr},
};

#[derive(Parser)]
#[command(
    name = "privtx-cli",
    about = "private-tx pool client for a live cluster"
)]
struct Cli {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
    /// Fee payer keypair (solana-keygen JSON); also the issuer and the
    /// depositor's owner in this demo.
    #[arg(long)]
    keypair: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Airdrop SOL to the payer (test validators only).
    Airdrop {
        #[arg(long, default_value_t = 10.0)]
        sol: f64,
    },
    /// Register a verifying key (gnark `vk.bin`) with the verifier program
    /// and print its key account.
    RegisterVk { vk: PathBuf },
    /// Create a token mint (6 decimals, payer as authority), a depositor
    /// token account funded with `--amount`, and an empty destination
    /// token account. Prints all three.
    TokenSetup {
        #[arg(long)]
        amount: u64,
    },
    /// Create the pool: a vault token account owned by the vault authority
    /// PDA, the pool account, and `InitializePool`.
    CreatePool {
        #[arg(long)]
        token_mint: String,
        #[arg(long)]
        mint_vk: String,
        #[arg(long)]
        burn_vk: String,
        #[arg(long)]
        transfer_vk: String,
        /// The custodian's audit key file written by `privtx audit-keygen`.
        #[arg(long)]
        audit_key: PathBuf,
        /// Custodian address (defaults to the payer).
        #[arg(long)]
        custodian: Option<String>,
    },
    /// Submit a `Mint` (shield) from a `privtx shield` proof file.
    Shield {
        #[arg(long)]
        pool: String,
        #[arg(long)]
        source: String,
        proof: PathBuf,
    },
    /// Submit a `Transfer` from a `privtx transfer` proof file.
    Transfer {
        #[arg(long)]
        pool: String,
        proof: PathBuf,
    },
    /// Submit a `Burn` (unshield) from a `privtx unshield` proof file.
    Unshield {
        #[arg(long)]
        pool: String,
        proof: PathBuf,
    },
    /// Index the pool from its transaction history and write the ledger
    /// (leaves, recipient blobs, nullifiers) for `privtx scan`.
    Ledger {
        #[arg(long)]
        pool: String,
        #[arg(long, default_value = "ledger.json")]
        out: PathBuf,
    },
    /// Show the pool account: supply, leaves, root, keys; and a token
    /// account's balance with `--token-account`.
    Info {
        #[arg(long)]
        pool: String,
        #[arg(long)]
        token_account: Vec<String>,
    },
    /// Print an address as hex (what `privtx` takes for `-pool` and
    /// `-destination`).
    Hex { address: String },
}

fn addr(s: &str) -> Result<Address> {
    Address::from_str(s).map_err(|e| anyhow!("{s}: {e}"))
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex_bytes(s)?;
    v.try_into().map_err(|_| anyhow!("want 32 bytes: {s}"))
}

fn arr<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into()
        .map_err(|_| anyhow!("want {N} bytes, got {}", v.len()))
}

struct Client {
    rpc: RpcClient,
    payer: Keypair,
}

impl Client {
    fn send(&self, instructions: &[Instruction], extra_signers: &[&Keypair]) -> Result<Signature> {
        let blockhash = self.rpc.get_latest_blockhash()?;
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend(extra_signers);
        let tx = Transaction::new_signed_with_payer(
            instructions,
            Some(&self.payer.pubkey()),
            &signers,
            blockhash,
        );
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .context("transaction failed")?;
        Ok(sig)
    }

    fn rent(&self, len: usize) -> Result<u64> {
        Ok(self.rpc.get_minimum_balance_for_rent_exemption(len)?)
    }

    /// System `CreateAccount` for a fresh keypair.
    fn create_account_ix(&self, new: &Keypair, len: usize, owner: &Address) -> Result<Instruction> {
        Ok(solana_system_interface::instruction::create_account(
            &self.payer.pubkey(),
            &new.pubkey(),
            self.rent(len)?,
            len as u64,
            owner,
        ))
    }

    /// Registers a verifying key through the verifier's staging flow.
    fn register_vk(&self, key: &OnChainKey) -> Result<Address> {
        let n = key.num_public_inputs();
        let verifier = private_tx_pool::VERIFIER_ID;
        let key_pda = find_key_address(&verifier, &key.hash()).0;
        if self.rpc.get_account(&key_pda).is_ok() {
            println!("key already registered");
            return Ok(key_pda);
        }
        let staging = Keypair::new();
        let authority = self.payer.pubkey();
        let [create, init] = verifier_ix::create_staging(
            &verifier,
            &authority,
            &authority,
            &staging.pubkey(),
            n as u16,
            self.rent(staging_account_len(n))?,
        );
        self.send(&[create, init], &[&staging])?;
        for w in verifier_ix::write_body(&verifier, &authority, &staging.pubkey(), key.body(), 800)
        {
            self.send(&[w], &[])?;
        }
        self.send(
            &[verifier_ix::publish(
                &verifier,
                &authority,
                &authority,
                &staging.pubkey(),
                &key_pda,
            )],
            &[],
        )?;
        Ok(key_pda)
    }
}

/// SPL Token instruction builders, the few the demo needs.
mod token {
    use super::*;
    pub const ID: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    pub const MINT_LEN: usize = 82;

    /// `InitializeMint2`: decimals, mint authority, no freeze authority.
    pub fn initialize_mint(mint: &Address, authority: &Address, decimals: u8) -> Instruction {
        let mut data = vec![20, decimals];
        data.extend_from_slice(authority.as_array());
        data.push(0);
        Instruction {
            program_id: ID,
            accounts: vec![AccountMeta::new(*mint, false)],
            data,
        }
    }

    /// `InitializeAccount3`.
    pub fn initialize_account(account: &Address, mint: &Address, owner: &Address) -> Instruction {
        let mut data = vec![18];
        data.extend_from_slice(owner.as_array());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
            ],
            data,
        }
    }

    /// `MintTo`.
    pub fn mint_to(
        mint: &Address,
        dest: &Address,
        authority: &Address,
        amount: u64,
    ) -> Instruction {
        let mut data = vec![7];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*dest, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }
}

#[derive(serde::Deserialize)]
struct AuditKeyFile {
    pk_x: String,
    pk_y: String,
}

#[derive(serde::Deserialize)]
struct ProofFile {
    proof: String,
    public: String,
}

fn parse_proof(p: &ProofFile) -> Result<([u8; PROOF_SIZE], Vec<[u8; 32]>)> {
    let proof = gnark::parse_proof(&hex_bytes(&p.proof)?).map_err(|e| anyhow!("proof: {e:?}"))?;
    let inputs = gnark::parse_public_witness(&hex_bytes(&p.public)?)
        .map_err(|e| anyhow!("public witness: {e:?}"))?;
    Ok((proof.0, arkworks::public_inputs(&inputs)))
}

#[derive(serde::Deserialize)]
struct ShieldFile {
    #[serde(flatten)]
    proof: ProofFile,
    commitment: String,
    value: u64,
    audit_blob: String,
    enc_blob: String,
}

#[derive(serde::Deserialize)]
struct TransferFile {
    #[serde(flatten)]
    proof: ProofFile,
    root: String,
    nullifiers: Vec<String>,
    commitments: Vec<String>,
    audit_blob: String,
    enc_blobs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct UnshieldFile {
    #[serde(flatten)]
    proof: ProofFile,
    root: String,
    nullifier: String,
    value: u64,
    forced: bool,
    destination: String,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    Ok(serde_json::from_slice(
        &std::fs::read(path).with_context(|| path.display().to_string())?,
    )?)
}

/// Reads the pool account and its config as the instruction builders need.
fn pool_config(rpc: &RpcClient, pool: &Address) -> Result<(Vec<u8>, PoolConfig)> {
    let mut data = rpc.get_account(pool)?.data;
    if data.len() != POOL_ACCOUNT_LEN {
        bail!("{pool} is not a pool account");
    }
    let config = {
        let p = Pool::from_bytes(&mut data).map_err(|e| anyhow!("pool account: {e:?}"))?;
        PoolConfig {
            custodian: Address::new_from_array(*p.custodian()),
            issuer: Address::new_from_array(*p.issuer()),
            mint_key: Address::new_from_array(*p.mint_key()),
            burn_key: Address::new_from_array(*p.burn_key()),
            transfer_key: Address::new_from_array(*p.transfer_key()),
            token_program: Address::new_from_array(*p.token_program()),
            token_mint: Address::new_from_array(*p.token_mint()),
            vault: Address::new_from_array(*p.vault()),
            audit_pk: *p.audit_pk(),
        }
    };
    Ok((data, config))
}

fn token_balance(rpc: &RpcClient, account: &Address) -> Result<u64> {
    let data = rpc.get_account(account)?.data;
    if data.len() < token_account::LEN {
        bail!("{account} is not a token account");
    }
    Ok(u64::from_le_bytes(
        data[token_account::AMOUNT_OFFSET..token_account::AMOUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    ))
}

/// Every instruction of the pool program in the pool's history, oldest
/// first, as an indexer would collect them.
fn pool_instructions(rpc: &RpcClient, pool: &Address) -> Result<Vec<Instruction>> {
    // Confirmed, not the default finalized: the demo reads back what it
    // just sent. Pages of up to 1,000 signatures, newest first, walked
    // back with `before` until exhausted.
    let mut sigs = Vec::new();
    let mut before = None;
    loop {
        let page = rpc.get_signatures_for_address_with_config(
            pool,
            GetConfirmedSignaturesForAddress2Config {
                before,
                commitment: Some(CommitmentConfig::confirmed()),
                ..Default::default()
            },
        )?;
        let Some(last) = page.last() else { break };
        before = Some(Signature::from_str(&last.signature)?);
        sigs.extend(page);
    }
    sigs.reverse();
    let mut out = Vec::new();
    for s in sigs {
        if s.err.is_some() {
            continue;
        }
        let sig = Signature::from_str(&s.signature)?;
        let tx = rpc.get_transaction_with_config(
            &sig,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )?;
        let decoded = tx
            .transaction
            .transaction
            .decode()
            .ok_or_else(|| anyhow!("undecodable transaction {sig}"))?;
        let keys = decoded.message.static_account_keys().to_vec();
        for ci in decoded.message.instructions() {
            let program_id = keys[ci.program_id_index as usize];
            if program_id != private_tx_pool::ID {
                continue;
            }
            out.push(Instruction {
                program_id,
                accounts: ci
                    .accounts
                    .iter()
                    .map(|i| AccountMeta::new_readonly(keys[*i as usize], false))
                    .collect(),
                data: ci.data.clone(),
            });
        }
    }
    Ok(out)
}

#[derive(serde::Serialize)]
struct LedgerFile {
    leaves: Vec<String>,
    blobs: Vec<String>,
    nullifiers: Vec<String>,
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let payer = read_keypair_file(&cli.keypair).map_err(|e| anyhow!("keypair: {e}"))?;
    let c = Client {
        rpc: RpcClient::new_with_commitment(cli.url.clone(), CommitmentConfig::confirmed()),
        payer,
    };
    match cli.cmd {
        Cmd::Airdrop { sol } => {
            let sig = c
                .rpc
                .request_airdrop(&c.payer.pubkey(), (sol * 1e9) as u64)?;
            c.rpc.confirm_transaction(&sig)?;
            while c.rpc.get_balance(&c.payer.pubkey())? == 0 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            println!(
                "payer {} balance {} lamports",
                c.payer.pubkey(),
                c.rpc.get_balance(&c.payer.pubkey())?
            );
        }
        Cmd::RegisterVk { vk } => {
            let key = gnark::parse_verifying_key(&std::fs::read(&vk)?)
                .map_err(|e| anyhow!("vk.bin: {e:?}"))?;
            key.validate_for_publish()
                .map_err(|e| anyhow!("vk: {e:?}"))?;
            let pda = c.register_vk(&key)?;
            println!("{pda}");
        }
        Cmd::TokenSetup { amount } => {
            let mint = Keypair::new();
            let depositor = Keypair::new();
            let destination = Keypair::new();
            let me = c.payer.pubkey();
            let sig = c.send(
                &[
                    c.create_account_ix(&mint, token::MINT_LEN, &token::ID)?,
                    token::initialize_mint(&mint.pubkey(), &me, 6),
                    c.create_account_ix(&depositor, token_account::LEN, &token::ID)?,
                    token::initialize_account(&depositor.pubkey(), &mint.pubkey(), &me),
                    c.create_account_ix(&destination, token_account::LEN, &token::ID)?,
                    token::initialize_account(&destination.pubkey(), &mint.pubkey(), &me),
                    token::mint_to(&mint.pubkey(), &depositor.pubkey(), &me, amount),
                ],
                &[&mint, &depositor, &destination],
            )?;
            println!("token_mint {}", mint.pubkey());
            println!("depositor {}", depositor.pubkey());
            println!("destination {}", destination.pubkey());
            println!("signature {sig}");
        }
        Cmd::CreatePool {
            token_mint,
            mint_vk,
            burn_vk,
            transfer_vk,
            audit_key,
            custodian,
        } => {
            let token_mint = addr(&token_mint)?;
            let audit: AuditKeyFile = read_json(&audit_key)?;
            let mut audit_pk = [0u8; 64];
            audit_pk[..32].copy_from_slice(&hex32(&audit.pk_x)?);
            audit_pk[32..].copy_from_slice(&hex32(&audit.pk_y)?);
            let pool = Keypair::new();
            let vault = Keypair::new();
            let vault_authority = pool_ix::find_vault_authority(&pool.pubkey()).0;
            let config = PoolConfig {
                custodian: custodian
                    .map(|s| addr(&s))
                    .transpose()?
                    .unwrap_or(c.payer.pubkey()),
                issuer: c.payer.pubkey(),
                mint_key: addr(&mint_vk)?,
                burn_key: addr(&burn_vk)?,
                transfer_key: addr(&transfer_vk)?,
                token_program: token::ID,
                token_mint,
                vault: vault.pubkey(),
                audit_pk,
            };
            let [create_pool, init] = pool_ix::create_pool(
                &c.payer.pubkey(),
                &pool.pubkey(),
                c.rent(POOL_ACCOUNT_LEN)?,
                &config,
            );
            let sig = c.send(
                &[
                    c.create_account_ix(&vault, token_account::LEN, &token::ID)?,
                    token::initialize_account(&vault.pubkey(), &token_mint, &vault_authority),
                    create_pool,
                    init,
                ],
                &[&vault, &pool],
            )?;
            println!("pool {}", pool.pubkey());
            println!("pool_hex {}", hx(pool.pubkey().as_array()));
            println!("vault {}", vault.pubkey());
            println!("signature {sig}");
        }
        Cmd::Shield {
            pool,
            source,
            proof,
        } => {
            let pool = addr(&pool)?;
            let (_, config) = pool_config(&c.rpc, &pool)?;
            let f: ShieldFile = read_json(&proof)?;
            let (proof_bytes, inputs) = parse_proof(&f.proof)?;
            let commitment = hex32(&f.commitment)?;
            if inputs[0] != commitment {
                bail!("proof file: public input 0 is not the commitment");
            }
            let ix = pool_ix::mint(
                &pool,
                &config,
                &addr(&source)?,
                &c.payer.pubkey(),
                &proof_bytes,
                &commitment,
                f.value,
                &arr::<{ blob::audit_len(1) }>(&hex_bytes(&f.audit_blob)?)?,
                &arr::<{ blob::RECIPIENT_LEN }>(&hex_bytes(&f.enc_blob)?)?,
            );
            let sig = c.send(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(300_000),
                    ix,
                ],
                &[],
            )?;
            println!("shielded {} into {}", f.value, hx(&commitment));
            println!("signature {sig}");
        }
        Cmd::Transfer { pool, proof } => {
            let pool = addr(&pool)?;
            let (mut data, config) = pool_config(&c.rpc, &pool)?;
            let f: TransferFile = read_json(&proof)?;
            let (proof_bytes, inputs) = parse_proof(&f.proof)?;
            let nullifiers = [hex32(&f.nullifiers[0])?, hex32(&f.nullifiers[1])?];
            let commitments = [hex32(&f.commitments[0])?, hex32(&f.commitments[1])?];
            if inputs[1] != nullifiers[0] || inputs[3] != commitments[0] {
                bail!("proof file: public inputs disagree with the statement");
            }
            let enc_blobs: Vec<u8> = f
                .enc_blobs
                .iter()
                .map(|b| hex_bytes(b))
                .collect::<Result<Vec<_>>>()?
                .concat();
            let root = hex32(&f.root)?;
            let slot = Pool::from_bytes(&mut data)
                .map_err(|e| anyhow!("{e:?}"))?
                .find_root(&root)
                .ok_or_else(|| {
                    anyhow!("the proof's root is no longer in the pool's history; re-index and re-prove")
                })?;
            let ix = pool_ix::transfer(
                &pool,
                &config,
                &c.payer.pubkey(),
                &proof_bytes,
                slot as u8,
                &nullifiers,
                &commitments,
                &arr::<{ blob::audit_len(2) }>(&hex_bytes(&f.audit_blob)?)?,
                &arr::<{ 2 * blob::RECIPIENT_LEN }>(&enc_blobs)?,
            );
            let sig = c.send(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                    ix,
                ],
                &[],
            )?;
            println!(
                "transferred: nullifiers {} {}",
                hx(&nullifiers[0]),
                hx(&nullifiers[1])
            );
            println!(
                "new commitments {} {}",
                hx(&commitments[0]),
                hx(&commitments[1])
            );
            println!("signature {sig}");
        }
        Cmd::Unshield { pool, proof } => {
            let pool = addr(&pool)?;
            let (_, config) = pool_config(&c.rpc, &pool)?;
            let f: UnshieldFile = read_json(&proof)?;
            if f.forced {
                bail!("a forced burn needs the custodian's signature; this command only signs as the payer");
            }
            let (proof_bytes, inputs) = parse_proof(&f.proof)?;
            let nullifier = hex32(&f.nullifier)?;
            if inputs[1] != nullifier {
                bail!("proof file: public input 1 is not the nullifier");
            }
            let destination = Address::new_from_array(hex32(&f.destination)?);
            let ix = pool_ix::burn(
                &pool,
                &config,
                &c.payer.pubkey(),
                &proof_bytes,
                &hex32(&f.root)?,
                &nullifier,
                f.value,
                f.forced,
                &destination,
            );
            let sig = c.send(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(300_000),
                    ix,
                ],
                &[],
            )?;
            println!("unshielded {} to {destination}", f.value);
            println!("signature {sig}");
        }
        Cmd::Ledger { pool, out } => {
            let pool = addr(&pool)?;
            let mut idx = Indexer::default();
            let ixs = pool_instructions(&c.rpc, &pool)?;
            for ix in &ixs {
                idx.observe(ix);
            }
            let file = LedgerFile {
                leaves: idx.leaves.iter().map(|l| hx(l)).collect(),
                blobs: idx.blobs.iter().map(|b| hx(b)).collect(),
                nullifiers: idx.nullifiers.iter().map(|n| hx(n)).collect(),
            };
            std::fs::write(&out, serde_json::to_vec_pretty(&file)?)?;
            let (data, _) = pool_config(&c.rpc, &pool)?;
            let mut data = data;
            let p = Pool::from_bytes(&mut data).map_err(|e| anyhow!("{e:?}"))?;
            let on_chain = *p.current_root();
            let rebuilt = idx.root(32);
            println!(
                "{} instructions, {} leaves, {} nullifiers; rebuilt root {} on-chain root {} ({})",
                ixs.len(),
                idx.leaves.len(),
                idx.nullifiers.len(),
                hx(&rebuilt),
                hx(&on_chain),
                if rebuilt == on_chain {
                    "match"
                } else {
                    "MISMATCH"
                }
            );
            println!("wrote {}", out.display());
        }
        Cmd::Info {
            pool,
            token_account,
        } => {
            let pool = addr(&pool)?;
            let (mut data, config) = pool_config(&c.rpc, &pool)?;
            let p = Pool::from_bytes(&mut data).map_err(|e| anyhow!("{e:?}"))?;
            println!("pool        {pool}");
            println!("supply      {}", p.supply());
            println!("leaves      {}", p.next_index());
            println!("root        {}", hx(p.current_root()));
            println!(
                "vault       {} (balance {})",
                config.vault,
                token_balance(&c.rpc, &config.vault)?
            );
            println!("token_mint  {}", config.token_mint);
            println!("issuer      {}", config.issuer);
            println!("custodian   {}", config.custodian);
            for t in token_account {
                let a = addr(&t)?;
                println!("{a}  balance {}", token_balance(&c.rpc, &a)?);
            }
        }
        Cmd::Hex { address } => println!("{}", hx(addr(&address)?.as_array())),
    }
    Ok(())
}
