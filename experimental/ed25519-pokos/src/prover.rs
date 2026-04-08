//! Prover-side entry points for the POKOS proof envelope.
//!
//! This module is responsible for everything the *prover* does:
//!
//! 1. **Key derivation** — [`derive_secret_key_material`] computes the
//!    full SHA-512 derivation chain from a `seed`, producing the PRF output,
//!    the Ed25519 signing seed (`sk_seed`), and the public hash of that seed.
//! 2. **Statement assembly** — [`statement_from_seed`] and the private
//!    `statement_from_derived` helper turn derivation output into the
//!    [`SeedChainStatement`] that the STARK proof is bound to.
//! 3. **Proof generation** — [`gen_pokos`] orchestrates the STARK prover
//!    and wraps everything into a [`SeedChainProofEnvelope`] signed by the
//!    derived Ed25519 key.

use crate::sha512::prove_private_seed_chain;
use crate::{
    COMMIT_OF_SEED_DOMAIN, DERIVE_SK_DOMAIN, DerivedSecretKeyMaterial, DigestBytes,
    ED25519_SEED_LEN, HASH_OF_SK_DOMAIN, Seed, SeedChainProofEnvelope, SeedChainStatement,
    Sha512ProofBundle, authentication_transcript, encode_domain_message, sha512,
};
use curve25519::ed_sigs::{SigningKey, VerificationKeyBytes};

/// Computes the public seed commitment: `SHA512(COMMIT_OF_SEED_DOMAIN || seed)`.
///
/// This is the value published as `commit_of_seed` in the [`SeedChainStatement`].
/// It binds the proof to a specific seed without revealing it.
pub fn commit_of_seed(seed: Seed) -> DigestBytes {
    sha512(&encode_domain_message(&COMMIT_OF_SEED_DOMAIN, &seed))
}

/// Derives all secret material from `seed`.
///
/// Executes the full SHA-512 derivation chain:
///
/// ```text
/// prf_output = SHA512(DERIVE_SK_DOMAIN || seed)
/// sk_seed    = prf_output[0..32]
/// hash_of_sk = SHA512(HASH_OF_SK_DOMAIN || sk_seed)
/// auth_key   = Ed25519 verification key for sk_seed
/// ```
///
/// The returned [`DerivedSecretKeyMaterial`] is the prover's private witness.
/// It should be treated as sensitive and not persisted beyond the proof
/// generation call.
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

/// Computes the public [`SeedChainStatement`] from a seed.
///
/// This is a convenience wrapper that calls [`derive_secret_key_material`] and
/// [`commit_of_seed`] and packs the results into a statement.  Useful when a
/// caller needs the public outputs without running the full proof.
pub fn statement_from_seed(seed: Seed) -> SeedChainStatement {
    statement_from_derived(seed, &derive_secret_key_material(seed))
}

/// Generates a complete [`SeedChainProofEnvelope`] for `seed`.
///
/// This is the main prover entry point.  It:
/// 1. Derives all secret key material from `seed` (one pass through the chain).
/// 2. Assembles the public [`SeedChainStatement`].
/// 3. Runs the Plonky3 STARK prover over the three-segment SHA-512 AIR.
/// 4. Signs the authentication transcript with the derived Ed25519 key.
/// 5. Returns the fully assembled [`SeedChainProofEnvelope`].
///
/// # Errors
///
/// Returns `Err(String)` if the STARK prover fails (e.g. internal Plonky3
/// error) or if the proof settings do not meet the minimum verifier policy.
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

/// Builds a [`SeedChainStatement`] from an already-derived witness, avoiding a
/// redundant call to [`derive_secret_key_material`].
fn statement_from_derived(seed: Seed, derived: &DerivedSecretKeyMaterial) -> SeedChainStatement {
    SeedChainStatement {
        commit_of_seed: commit_of_seed(seed),
        hash_of_sk: derived.hash_of_sk,
    }
}

/// Runs the Plonky3 STARK prover over the three-segment SHA-512 seed chain and
/// returns the sealed proof bytes as a [`Sha512ProofBundle`].
pub(crate) fn prove_sha512_bundle(seed: Seed) -> Result<Sha512ProofBundle, String> {
    let sealed = prove_private_seed_chain(seed)?;
    Ok(Sha512ProofBundle {
        sealed_proof: sealed.sealed_proof,
    })
}
