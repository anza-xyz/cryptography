use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig};
use serde::{Deserialize, Serialize};

mod segment_chain;

pub(crate) use segment_chain::{
    Sha512SegmentChainProof, deserialize_segment_chain_proof, serialize_segment_chain_proof,
};

pub type Val = KoalaBear;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
const MIN_VERIFIER_LOG_FINAL_POLY_LEN: usize = 4;
const MIN_VERIFIER_LOG_BLOWUP: usize = 3;
const MIN_VERIFIER_NUM_QUERIES: usize = 2;
const MIN_VERIFIER_COMMIT_POW_BITS: usize = 1;
const MIN_VERIFIER_QUERY_POW_BITS: usize = 1;
const MAX_INNER_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// Concrete Plonky3 STARK configuration used by this crate.
pub type Sha512StarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// A serialisable Plonky3 STARK proof under [`Sha512StarkConfig`].
pub type Sha512StarkProof = Proof<Sha512StarkConfig>;

/// FRI and transcript parameters for the STARK prover and verifier.
///
/// Both prover and verifier must use identical settings.
///
/// Defaults are a stronger production-oriented profile for this crate, not an audited policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha512ProofSettings {
    /// Log2 of FRI blowup factor.
    pub log_blowup: usize,
    /// Log2 of FRI final polynomial length.
    pub log_final_poly_len: usize,
    /// Number of FRI queries.
    pub num_queries: usize,
    /// Commit-phase proof-of-work bits.
    pub commit_proof_of_work_bits: usize,
    /// Query-phase proof-of-work bits.
    pub query_proof_of_work_bits: usize,
    /// Seed for the Fiat-Shamir transcript challenger.
    pub rng_seed: u64,
}

impl Default for Sha512ProofSettings {
    fn default() -> Self {
        Self {
            log_blowup: 3,
            log_final_poly_len: 5,
            num_queries: 28,
            commit_proof_of_work_bits: 16,
            query_proof_of_work_bits: 16,
            rng_seed: 1,
        }
    }
}

pub(crate) fn setup_config(settings: Sha512ProofSettings) -> Sha512StarkConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: settings.log_blowup,
        log_final_poly_len: settings.log_final_poly_len,
        num_queries: settings.num_queries,
        commit_proof_of_work_bits: settings.commit_proof_of_work_bits,
        query_proof_of_work_bits: settings.query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(settings.rng_seed.to_le_bytes().to_vec(), byte_hash);
    Sha512StarkConfig::new(pcs, challenger)
}

pub(crate) fn meets_minimum_verifier_policy(settings: Sha512ProofSettings) -> bool {
    settings.log_final_poly_len >= MIN_VERIFIER_LOG_FINAL_POLY_LEN
        && settings.log_blowup >= MIN_VERIFIER_LOG_BLOWUP
        && settings.num_queries >= MIN_VERIFIER_NUM_QUERIES
        && settings.commit_proof_of_work_bits >= MIN_VERIFIER_COMMIT_POW_BITS
        && settings.query_proof_of_work_bits >= MIN_VERIFIER_QUERY_POW_BITS
}

pub(crate) fn validate_settings_for_proving(settings: Sha512ProofSettings) -> Result<(), String> {
    if !meets_minimum_verifier_policy(settings) {
        return Err("proof settings do not meet minimum verifier policy".to_string());
    }
    Ok(())
}
