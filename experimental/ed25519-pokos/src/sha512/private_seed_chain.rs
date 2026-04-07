use super::{
    INITIAL_STATE, Sha512Circuit, Sha512ProofSettings, Sha512SegmentChainProof, Sha512StarkConfig,
    air::{MessageAirBundle, PrivateSeedChainBlocks, Sha512RoundAir},
    deserialize_segment_chain_proof,
    proof_api::{meets_minimum_verifier_policy, setup_config, validate_settings_for_proving},
    serialize_segment_chain_proof,
};
use crate::{
    Seed, derive_secret_key_material,
    private_seed_chain::{PrivateSeedChainWitness, SegmentKind, segment_block},
};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};

pub(crate) use crate::private_seed_chain::PrivateSeedChainPublic;

/// All data needed to run the Plonky3 prover for one seed chain.
///
/// `air_bundle` is always present.  `public` and `blocks` are only available
/// in test builds, where they are used to check AIR trace correctness.
pub(crate) struct PrivateSeedChainBundle {
    #[cfg(test)]
    pub(crate) public: PrivateSeedChainPublic,
    #[cfg(test)]
    pub(crate) blocks: PrivateSeedChainBlocks,
    pub(crate) air_bundle: MessageAirBundle,
}

/// A serialized Plonky3 STARK proof for the private seed chain, ready for transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedPrivateSeedChainProof {
    pub(crate) sealed_proof: Vec<u8>,
}

/// Constructs the [`PrivateSeedChainBundle`] (AIR traces + public values) for `seed`.
///
/// This builds the witness, the three padded SHA-512 blocks, and the full
/// main + preprocessed Plonky3 trace matrices, but does **not** run the prover.
/// Call [`prove_private_seed_chain`] to also produce the STARK proof.
pub(crate) fn build_private_seed_chain_bundle(seed: Seed) -> PrivateSeedChainBundle {
    let witness = witness_from_seed(seed);
    let blocks = blocks_from_witness(witness);
    let air_bundle = Sha512Circuit::build_private_seed_chain_air_bundle(&blocks);

    PrivateSeedChainBundle {
        #[cfg(test)]
        public: crate::private_seed_chain::public_from_witness(witness),
        #[cfg(test)]
        blocks,
        air_bundle,
    }
}

/// Proves the private seed chain for `seed` using the default [`Sha512ProofSettings`].
///
/// Returns a [`SealedPrivateSeedChainProof`] on success, or a string error if
/// the prover fails or the settings fail policy validation.
pub(crate) fn prove_private_seed_chain(seed: Seed) -> Result<SealedPrivateSeedChainProof, String> {
    prove_private_seed_chain_with_settings(seed, Sha512ProofSettings::default())
}

/// Proves the private seed chain for `seed` with explicit `settings`.
///
/// Validates that `settings` meet the minimum verifier policy before running
/// the prover.  Returns an error if validation fails or if the Plonky3 prover
/// encounters an internal error.
///
/// The resulting [`SealedPrivateSeedChainProof`] contains only the Plonky3
/// proof bytes and the settings.  The preprocessed commitment is embedded
/// inside the Plonky3 proof structure and is validated implicitly during
/// verification: the verifier independently reconstructs the expected VK from
/// `verifier_template_blocks()` and passes it to `verify_with_preprocessed`.
pub(crate) fn prove_private_seed_chain_with_settings(
    seed: Seed,
    settings: Sha512ProofSettings,
) -> Result<SealedPrivateSeedChainProof, String> {
    let bundle = build_private_seed_chain_bundle(seed);
    validate_settings_for_proving(settings)?;
    let config = setup_config(settings);
    let air = Sha512RoundAir::new(bundle.air_bundle.preprocessed.clone());
    let (preprocessed_prover_data, _) =
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
    let sealed_proof = serialize_segment_chain_proof(&Sha512SegmentChainProof { proof, settings })?;
    Ok(SealedPrivateSeedChainProof { sealed_proof })
}

/// Verifies a sealed seed-chain proof against `public` using the default settings.
///
/// Returns `true` if and only if:
/// - the proof deserializes successfully,
/// - the proof was produced with the default [`Sha512ProofSettings`],
/// - the verifier's independently reconstructed preprocessed VK (from
///   zero-payload template blocks) matches the commitment in the proof, and
/// - the Plonky3 STARK proof is valid for the given public values.
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

/// Verifies a sealed seed-chain proof against `public` with explicit `settings`.
///
/// Fails fast (returns `false`) if:
/// - `settings` do not meet the minimum verifier policy,
/// - the proof was produced with different settings than supplied here, or
/// - the Plonky3 verifier rejects the proof.
///
/// The preprocessed commitment check is performed inside Plonky3: the verifier
/// reconstructs the expected VK from `verifier_template_blocks()` (zero-payload
/// blocks with the correct domain structure) and passes it to
/// `verify_with_preprocessed`, which enforces that the prover's committed
/// preprocessed trace matches.
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

    let public_values = public_values_from_statement(public);
    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &public_values,
        Some(&expected_vk),
    )
    .is_ok()
}

fn witness_from_seed(seed: Seed) -> PrivateSeedChainWitness {
    PrivateSeedChainWitness {
        seed,
        sk_seed: derive_secret_key_material(seed).sk_seed,
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
        commit: segment_block(SegmentKind::Commit, zero),
        derive: segment_block(SegmentKind::Derive, zero),
        hash_sk: segment_block(SegmentKind::HashSk, zero),
    }
}

fn blocks_from_witness(witness: PrivateSeedChainWitness) -> PrivateSeedChainBlocks {
    PrivateSeedChainBlocks {
        commit: segment_block(SegmentKind::Commit, witness.seed),
        derive: segment_block(SegmentKind::Derive, witness.seed),
        hash_sk: segment_block(SegmentKind::HashSk, witness.sk_seed),
    }
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
    fn air_bundle_final_digest_matches_public_hash() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let trace = Sha512Circuit::compress_block(&INITIAL_STATE, &bundle.blocks.hash_sk);
        let mut digest = [0_u8; 64];
        for (i, chunk) in digest.chunks_exact_mut(8).enumerate() {
            let word = INITIAL_STATE[i].wrapping_add(trace.round_states[80][i]);
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        assert_eq!(digest, bundle.public.hash_of_sk);
    }

    #[test]
    fn prover_and_verifier_preprocessed_commitments_match() {
        let bundle = build_private_seed_chain_bundle(sample_seed());
        let config = setup_config(Sha512ProofSettings::default());
        let prover_air = Sha512RoundAir::new(bundle.air_bundle.preprocessed.clone());
        let (_, prover_vk) = setup_preprocessed::<Sha512StarkConfig, _>(
            &config,
            &prover_air,
            bundle.air_bundle.degree_bits,
        )
        .unwrap();

        let verifier_bundle =
            Sha512Circuit::build_private_seed_chain_air_bundle(&verifier_template_blocks());
        let verifier_air = Sha512RoundAir::new(verifier_bundle.preprocessed);
        let (_, verifier_vk) = setup_preprocessed::<Sha512StarkConfig, _>(
            &config,
            &verifier_air,
            verifier_bundle.degree_bits,
        )
        .unwrap();

        assert_eq!(prover_vk.commitment, verifier_vk.commitment);
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
