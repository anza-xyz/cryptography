//! Prover-side entry points for the active proof envelope.
//!
//! This module derives the public statement from `seed`, proves the internal SHA-512
//! seed-chain relation, and signs the outer transcript with the derived Ed25519 key.

use crate::sha512::prove_private_seed_chain;
use crate::{
    COMMIT_OF_SEED_DOMAIN, DERIVE_SK_DOMAIN, DerivedSecretKeyMaterial, DigestBytes,
    ED25519_SEED_LEN, HASH_OF_SK_DOMAIN, Seed, SeedChainProofEnvelope, SeedChainStatement,
    Sha512ProofBundle, authentication_transcript, encode_domain_message, sha512,
};
use curve25519::ed_sigs::{SigningKey, VerificationKeyBytes};

pub fn commit_of_seed(seed: Seed) -> DigestBytes {
    sha512(&encode_domain_message(&COMMIT_OF_SEED_DOMAIN, &seed))
}

pub fn derive_secret_key_material(seed: Seed) -> DerivedSecretKeyMaterial {
    let prf_output = sha512(&encode_domain_message(&DERIVE_SK_DOMAIN, &seed));
    let mut sk_seed = [0_u8; ED25519_SEED_LEN];
    sk_seed.copy_from_slice(&prf_output[..ED25519_SEED_LEN]);

    let hash_of_sk = sha512(&encode_domain_message(&HASH_OF_SK_DOMAIN, &sk_seed));
    let authentication_key = VerificationKeyBytes::from(&SigningKey::from(sk_seed));

    DerivedSecretKeyMaterial {
        prf_output,
        sk_seed,
        hash_of_sk,
        authentication_key,
    }
}

pub fn statement_from_seed(seed: Seed) -> SeedChainStatement {
    statement_from_derived(seed, &derive_secret_key_material(seed))
}

pub fn gen_pokos(seed: Seed) -> Result<SeedChainProofEnvelope, String> {
    let derived = derive_secret_key_material(seed);
    let statement = statement_from_derived(seed, &derived);
    let signing_key = SigningKey::from(derived.sk_seed);
    let transcript = authentication_transcript(statement);

    Ok(SeedChainProofEnvelope {
        statement,
        sha512_proof: prove_sha512_bundle(seed)?,
        authentication_key: derived.authentication_key,
        authentication_signature: signing_key.sign(&transcript),
    })
}

fn statement_from_derived(seed: Seed, derived: &DerivedSecretKeyMaterial) -> SeedChainStatement {
    SeedChainStatement {
        commit_of_seed: commit_of_seed(seed),
        hash_of_sk: derived.hash_of_sk,
    }
}

pub(crate) fn prove_sha512_bundle(seed: Seed) -> Result<Sha512ProofBundle, String> {
    let sealed = prove_private_seed_chain(seed)?;
    Ok(Sha512ProofBundle {
        sealed_proof: sealed.sealed_proof,
    })
}
