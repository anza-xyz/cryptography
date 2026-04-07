use super::{
    INITIAL_STATE, Sha512Circuit, Sha512ProofSettings, Sha512SegmentChainProof, Sha512StarkConfig,
    air::{
        LIMBS_PER_WORD, MessageAirBundle, PREP_BLOCK_START_SELECTOR_COL,
        PREP_COMMIT_FINAL_SELECTOR_COL, PREP_DERIVE_FINAL_SELECTOR_COL, PREP_FINAL_SELECTOR_COL,
        PREP_FIXED_INIT_W_SELECTOR_COL, PREP_HASH_FINAL_SELECTOR_COL, PREP_INIT_W_SELECTOR_COL,
        PREP_PAYLOAD_WORD_SELECTOR_COL, PREP_PAYLOAD_WORD0_SELECTOR_COL,
        PREP_PAYLOAD_WORD1_SELECTOR_COL, PREP_PAYLOAD_WORD2_SELECTOR_COL,
        PREP_PAYLOAD_WORD3_SELECTOR_COL, PREP_ROUND_SELECTOR_COL, PREP_SEGMENT_COMMIT_SELECTOR_COL,
        PREP_SEGMENT_DERIVE_SELECTOR_COL, PREP_SEGMENT_HASH_SELECTOR_COL,
        PREP_TRANSITION_SELECTOR_COL, PrivateSeedChainBlocks, Sha512RoundAir, WORD_A, WORD_K,
        WORD_W, limb_col,
    },
    deserialize_segment_chain_proof,
    proof_api::{meets_minimum_verifier_policy, setup_config, validate_settings_for_proving},
    serialize_segment_chain_proof,
};
use crate::{
    COMMIT_OF_SEED_DOMAIN, DERIVE_SK_DOMAIN, DigestBytes, HASH_OF_SK_DOMAIN, Seed,
    fixed_single_block,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::{Digest, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateSeedChainWitness {
    pub(crate) seed: Seed,
    pub(crate) sk_seed: Seed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateSeedChainPublic {
    pub(crate) commit_of_seed: DigestBytes,
    pub(crate) hash_of_sk: DigestBytes,
}

pub(crate) struct PrivateSeedChainBundle {
    #[cfg(test)]
    pub(crate) public: PrivateSeedChainPublic,
    #[cfg(test)]
    pub(crate) blocks: PrivateSeedChainBlocks,
    pub(crate) air_bundle: MessageAirBundle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedPrivateSeedChainProof {
    pub(crate) sealed_proof: Vec<u8>,
}

pub(crate) fn build_private_seed_chain_bundle(seed: Seed) -> PrivateSeedChainBundle {
    let witness = witness_from_seed(seed);
    let blocks = blocks_from_witness(witness);
    let air_bundle = Sha512Circuit::build_private_seed_chain_air_bundle(&blocks);

    PrivateSeedChainBundle {
        #[cfg(test)]
        public: public_from_witness(witness),
        #[cfg(test)]
        blocks,
        air_bundle,
    }
}

pub(crate) fn prove_private_seed_chain(seed: Seed) -> Result<SealedPrivateSeedChainProof, String> {
    prove_private_seed_chain_with_settings(seed, Sha512ProofSettings::default())
}

pub(crate) fn prove_private_seed_chain_with_settings(
    seed: Seed,
    settings: Sha512ProofSettings,
) -> Result<SealedPrivateSeedChainProof, String> {
    let bundle = build_private_seed_chain_bundle(seed);
    validate_settings_for_proving(settings)?;
    let config = setup_config(settings);
    let air = Sha512RoundAir::new(bundle.air_bundle.preprocessed.clone());
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, bundle.air_bundle.degree_bits)
            .ok_or_else(|| {
                "failed to setup preprocessed data for private seed-chain proof".to_string()
            })?;
    let proof = prove_with_preprocessed(
        &config,
        &air,
        bundle.air_bundle.main,
        &bundle.air_bundle.final_public_values,
        Some(&preprocessed_prover_data),
    );
    let sealed_proof = serialize_segment_chain_proof(&Sha512SegmentChainProof {
        proof,
        preprocessed_commitment: preprocessed_vk.commitment,
        preprocessed_trace_digest: digest_preprocessed_trace(&bundle.air_bundle.preprocessed),
        final_state: bundle.air_bundle.final_state,
        digest: Sha512Circuit::state_to_digest(&bundle.air_bundle.final_state),
        settings,
    })?;
    Ok(SealedPrivateSeedChainProof { sealed_proof })
}

pub(crate) fn verify_private_seed_chain_statement(
    bundle: &SealedPrivateSeedChainProof,
    public: PrivateSeedChainPublic,
) -> bool {
    verify_private_seed_chain_statement_with_settings(
        bundle,
        public,
        Sha512ProofSettings::default(),
    )
}

pub(crate) fn verify_private_seed_chain_statement_with_settings(
    bundle: &SealedPrivateSeedChainProof,
    public: PrivateSeedChainPublic,
    settings: Sha512ProofSettings,
) -> bool {
    if !meets_minimum_verifier_policy(settings) {
        return false;
    }
    let Ok(proof) = deserialize_segment_chain_proof(&bundle.sealed_proof) else {
        return false;
    };
    if proof.settings != settings {
        return false;
    }

    let config = setup_config(settings);
    let air_bundle =
        Sha512Circuit::build_private_seed_chain_air_bundle(&verifier_template_blocks());
    let air = Sha512RoundAir::new(air_bundle.preprocessed.clone());
    let Some((_, expected_vk)) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, air_bundle.degree_bits)
    else {
        return false;
    };
    if proof.preprocessed_trace_digest != digest_preprocessed_trace(&air_bundle.preprocessed) {
        return false;
    }
    let verifier_vk = p3_uni_stark::PreprocessedVerifierKey::<Sha512StarkConfig> {
        width: expected_vk.width,
        degree_bits: expected_vk.degree_bits,
        commitment: proof.preprocessed_commitment,
    };

    let public_values = public_values_from_statement(public);
    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &public_values,
        Some(&verifier_vk),
    )
    .is_ok()
}

fn witness_from_seed(seed: Seed) -> PrivateSeedChainWitness {
    let derive_digest = Sha512Circuit::hash(&encode_fixed_message(&DERIVE_SK_DOMAIN, &seed));
    let mut sk_seed = [0_u8; 32];
    sk_seed.copy_from_slice(&derive_digest[..32]);
    PrivateSeedChainWitness { seed, sk_seed }
}

#[cfg(test)]
fn public_from_witness(witness: PrivateSeedChainWitness) -> PrivateSeedChainPublic {
    PrivateSeedChainPublic {
        commit_of_seed: Sha512Circuit::hash(&encode_fixed_message(
            &COMMIT_OF_SEED_DOMAIN,
            &witness.seed,
        )),
        hash_of_sk: Sha512Circuit::hash(&encode_fixed_message(
            &HASH_OF_SK_DOMAIN,
            &witness.sk_seed,
        )),
    }
}

pub(crate) fn public_values_from_statement(
    public: PrivateSeedChainPublic,
) -> [p3_koala_bear::KoalaBear; 16] {
    let mut values = [p3_koala_bear::KoalaBear::ZERO; 16];
    // The proof exposes the pre-feed-forward SHA-512 round state at row 80, while the public
    // statement exposes the post-feed-forward digest. Reconstruct the former by subtracting the
    // standard initial chaining value word-by-word modulo 2^64.
    for (i, chunk) in public.commit_of_seed.chunks_exact(8).take(8).enumerate() {
        let digest_word = u64::from_be_bytes(chunk.try_into().expect("commit digest word"));
        values[i] = super::ops::bb(digest_word.wrapping_sub(INITIAL_STATE[i]));
    }
    for (i, chunk) in public.hash_of_sk.chunks_exact(8).take(8).enumerate() {
        let digest_word = u64::from_be_bytes(chunk.try_into().expect("hash-of-sk digest word"));
        values[8 + i] = super::ops::bb(digest_word.wrapping_sub(INITIAL_STATE[i]));
    }
    values
}

fn verifier_template_blocks() -> PrivateSeedChainBlocks {
    let zero = [0_u8; 32];
    PrivateSeedChainBlocks {
        commit: fixed_single_block(&COMMIT_OF_SEED_DOMAIN, &zero),
        derive: fixed_single_block(&DERIVE_SK_DOMAIN, &zero),
        hash_sk: fixed_single_block(&HASH_OF_SK_DOMAIN, &zero),
    }
}

fn blocks_from_witness(witness: PrivateSeedChainWitness) -> PrivateSeedChainBlocks {
    PrivateSeedChainBlocks {
        commit: fixed_single_block(&COMMIT_OF_SEED_DOMAIN, &witness.seed),
        derive: fixed_single_block(&DERIVE_SK_DOMAIN, &witness.seed),
        hash_sk: fixed_single_block(&HASH_OF_SK_DOMAIN, &witness.sk_seed),
    }
}

fn encode_fixed_message(domain: &[u8; 32], payload: &Seed) -> [u8; 64] {
    let mut message = [0_u8; 64];
    message[..32].copy_from_slice(domain);
    message[32..].copy_from_slice(payload);
    message
}

fn digest_preprocessed_trace(
    trace: &p3_matrix::dense::RowMajorMatrix<p3_koala_bear::KoalaBear>,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for row_idx in 0..trace.height() {
        let row = trace.row_slice(row_idx).expect("preprocessed row exists");
        for word in WORD_A..WORD_A + 8 {
            for limb in 0..LIMBS_PER_WORD {
                let value = row[limb_col(word, limb)];
                hasher.update(value.as_canonical_u32().to_le_bytes());
            }
        }
        for limb in 0..LIMBS_PER_WORD {
            let value = row[limb_col(WORD_K, limb)];
            hasher.update(value.as_canonical_u32().to_le_bytes());
        }
        let include_w = row[PREP_FIXED_INIT_W_SELECTOR_COL] == p3_koala_bear::KoalaBear::ONE;
        for limb in 0..LIMBS_PER_WORD {
            let value = if include_w {
                row[limb_col(WORD_W, limb)]
            } else {
                p3_koala_bear::KoalaBear::ZERO
            };
            hasher.update(value.as_canonical_u32().to_le_bytes());
        }
        for col in [
            PREP_BLOCK_START_SELECTOR_COL,
            PREP_TRANSITION_SELECTOR_COL,
            PREP_ROUND_SELECTOR_COL,
            PREP_INIT_W_SELECTOR_COL,
            PREP_FINAL_SELECTOR_COL,
            PREP_SEGMENT_COMMIT_SELECTOR_COL,
            PREP_SEGMENT_DERIVE_SELECTOR_COL,
            PREP_SEGMENT_HASH_SELECTOR_COL,
            PREP_COMMIT_FINAL_SELECTOR_COL,
            PREP_DERIVE_FINAL_SELECTOR_COL,
            PREP_HASH_FINAL_SELECTOR_COL,
            PREP_PAYLOAD_WORD_SELECTOR_COL,
            PREP_FIXED_INIT_W_SELECTOR_COL,
            PREP_PAYLOAD_WORD0_SELECTOR_COL,
            PREP_PAYLOAD_WORD1_SELECTOR_COL,
            PREP_PAYLOAD_WORD2_SELECTOR_COL,
            PREP_PAYLOAD_WORD3_SELECTOR_COL,
        ] {
            hasher.update(row[col].as_canonical_u32().to_le_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512::air::{
        PREP_COMMIT_FINAL_SELECTOR_COL_FOR_TESTS, PREP_DERIVE_FINAL_SELECTOR_COL_FOR_TESTS,
        PREP_FIXED_INIT_W_SELECTOR_COL_FOR_TESTS, PREP_HASH_FINAL_SELECTOR_COL_FOR_TESTS,
        PREP_PAYLOAD_WORD_SELECTOR_COL_FOR_TESTS, PREP_SEGMENT_COMMIT_SELECTOR_COL_FOR_TESTS,
        PREP_SEGMENT_DERIVE_SELECTOR_COL_FOR_TESTS, PREP_SEGMENT_HASH_SELECTOR_COL_FOR_TESTS,
        PRIVATE_SEED_LIMB_BASE_FOR_TESTS, PRIVATE_SK_LIMB_BASE_FOR_TESTS,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_field::PrimeField32;
    use p3_matrix::Matrix;

    fn sample_seed() -> Seed {
        [7_u8; 32]
    }

    #[test]
    fn sealed_proof_round_trip_verifies() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let sealed = prove_private_seed_chain(sample_seed()).unwrap();

        assert!(verify_private_seed_chain_statement(&sealed, bundle.public));
    }

    #[test]
    fn sealed_proof_rejects_tampered_bytes() {
        let mut sealed = prove_private_seed_chain(sample_seed()).unwrap();
        sealed.sealed_proof[0] ^= 1;

        let public = build_private_seed_chain_bundle(sample_seed()).public;
        assert!(!verify_private_seed_chain_statement(&sealed, public));
    }

    #[test]
    fn statement_verifier_accepts_valid_public_statement() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let sealed = prove_private_seed_chain(sample_seed()).unwrap();

        assert!(verify_private_seed_chain_statement(&sealed, bundle.public));
    }

    #[test]
    fn statement_verifier_rejects_wrong_commitment() {
        let mut public = build_private_seed_chain_bundle(sample_seed()).public;
        let sealed = prove_private_seed_chain(sample_seed()).unwrap();
        public.commit_of_seed[0] ^= 1;

        assert!(!verify_private_seed_chain_statement(&sealed, public));
    }

    #[test]
    fn statement_verifier_rejects_wrong_hash_of_sk() {
        let mut public = build_private_seed_chain_bundle(sample_seed()).public;
        let sealed = prove_private_seed_chain(sample_seed()).unwrap();
        public.hash_of_sk[0] ^= 1;

        assert!(!verify_private_seed_chain_statement(&sealed, public));
    }

    #[test]
    fn statement_verifier_rejects_wrong_preprocessed_trace_digest() {
        let public = build_private_seed_chain_bundle(sample_seed()).public;
        let sealed = prove_private_seed_chain(sample_seed()).unwrap();
        let mut proof = deserialize_segment_chain_proof(&sealed.sealed_proof).unwrap();
        proof.preprocessed_trace_digest[0] ^= 1;
        let sealed = SealedPrivateSeedChainProof {
            sealed_proof: serialize_segment_chain_proof(&proof).unwrap(),
        };

        assert!(!verify_private_seed_chain_statement(&sealed, public));
    }

    #[test]
    fn air_bundle_final_digest_matches_public_hash() {
        let bundle = build_private_seed_chain_bundle(sample_seed());

        assert_eq!(
            Sha512Circuit::state_to_digest(&bundle.air_bundle.final_state),
            bundle.public.hash_of_sk
        );
    }

    #[test]
    fn air_bundle_marks_seed_chain_roles() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let prep = &bundle.air_bundle.preprocessed;

        let row = |r: usize| prep.row_slice(r).unwrap();
        let commit_row0 = row(0);
        let derive_row0 = row(128);
        let hash_row0 = row(256);

        assert_eq!(
            commit_row0[PREP_SEGMENT_COMMIT_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
        assert_eq!(
            derive_row0[PREP_SEGMENT_DERIVE_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
        assert_eq!(
            hash_row0[PREP_SEGMENT_HASH_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );

        assert_eq!(
            row(80)[PREP_COMMIT_FINAL_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
        assert_eq!(
            row(208)[PREP_DERIVE_FINAL_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
        assert_eq!(
            row(336)[PREP_HASH_FINAL_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );

        assert_eq!(
            row(4)[PREP_PAYLOAD_WORD_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
        assert_eq!(
            row(0)[PREP_FIXED_INIT_W_SELECTOR_COL_FOR_TESTS],
            p3_koala_bear::KoalaBear::ONE
        );
    }

    #[test]
    fn preprocessed_trace_hides_payload_w_words() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let prep = &bundle.air_bundle.preprocessed;

        for absolute_row in [4_usize, 5, 6, 7, 132, 133, 134, 135, 260, 261, 262, 263] {
            let row = prep.row_slice(absolute_row).unwrap();
            for limb in 0..4 {
                assert_eq!(
                    row[crate::sha512::air::LIMB_BASE_FOR_TESTS
                        + crate::sha512::air::WORD_W_FOR_TESTS
                            * crate::sha512::air::LIMBS_PER_WORD_FOR_TESTS
                        + limb],
                    p3_koala_bear::KoalaBear::ZERO
                );
            }
        }
    }

    #[test]
    fn main_trace_carries_private_seed_and_sk_words() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let main = &bundle.air_bundle.main;
        let row = main.row_slice(0).unwrap();

        let seed = sample_seed();
        for (word_idx, bytes) in seed.chunks_exact(8).enumerate() {
            let expected_seed = u64::from_be_bytes(bytes.try_into().unwrap());
            let expected_sk = u64::from_be_bytes(
                bundle.blocks.hash_sk[32 + word_idx * 8..40 + word_idx * 8]
                    .try_into()
                    .unwrap(),
            );
            let mut actual_seed = 0_u64;
            let mut actual_sk = 0_u64;
            for limb in 0..4 {
                actual_seed |= u64::from(
                    row[PRIVATE_SEED_LIMB_BASE_FOR_TESTS + word_idx * 4 + limb].as_canonical_u32(),
                ) << (16 * limb);
                actual_sk |= u64::from(
                    row[PRIVATE_SK_LIMB_BASE_FOR_TESTS + word_idx * 4 + limb].as_canonical_u32(),
                ) << (16 * limb);
            }
            assert_eq!(actual_seed, expected_seed);
            assert_eq!(actual_sk, expected_sk);
        }
    }

    #[test]
    fn statement_public_values_match_air_bundle() {
        let bundle = build_private_seed_chain_bundle(sample_seed());

        assert_eq!(
            public_values_from_statement(bundle.public),
            bundle.air_bundle.final_public_values
        );
    }
}
