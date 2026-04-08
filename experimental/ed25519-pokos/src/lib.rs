//! Proof of Knowledge of Seed (POKOS) for Ed25519.
//!
//! This crate proves, in zero knowledge, that the prover knows a seed that was used
//! to derive an Ed25519 secret key — without revealing the seed or the key itself.
//! The proof covers the full SHA-512 derivation chain and is authenticated with an
//! Ed25519 signature from the derived key.
//!
//! # Protocol shape
//!
//! The public statement is `(commit_of_seed, hash_of_sk)`.  The prover holds the
//! secret `seed` and proves the following chain in zero knowledge:
//!
//! ```text
//! commit_of_seed  = SHA512(domain_commit  || seed)
//! prf_output      = SHA512(domain_derive  || seed)
//! sk_seed         = prf_output[0..32]
//! hash_of_sk      = SHA512(domain_hash_sk || sk_seed)
//! ```
//!
//! All three SHA-512 evaluations are proved by a single Plonky3 STARK over the
//! SHA-512 compression function.  The outer envelope is then signed by the Ed25519
//! key derived from `sk_seed`, binding the proof to the key owner without exposing
//! either the seed or the secret key.
//!
//! # Security note
//!
//! This is a *temporary* construction.  It does not prove `sk -> pk` inside the
//! circuit; that link is enforced externally by the Ed25519 signature.  A fully
//! sound end-to-end statement would expose `pk` as a public input and prove the
//! complete chain `seed -> sk -> pk` in circuit.  That stronger version is deferred
//! because in-circuit Ed25519 group operations currently exceed practical circuit
//! sizes.  See [`readme.md`](../readme.md) for the full design discussion.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use ed25519_pokos::{Seed, gen_pokos, verify_pokos, serialize_proof, deserialize_proof};
//!
//! let seed: Seed = [7_u8; 32];
//!
//! // Prover side
//! let proof = gen_pokos(seed)?;
//! let bytes = serialize_proof(&proof);
//!
//! // Verifier side
//! let proof = deserialize_proof(&bytes)?;
//! verify_pokos(&proof)?;
//! # Ok::<(), String>(())
//! ```

use curve25519::ed_sigs::{Signature, VerificationKeyBytes};
use sha2::{Digest, Sha512};

// ─── Byte-length constants ────────────────────────────────────────────────────

/// Byte length of a SHA-512 digest (64 bytes = 512 bits).
pub const SHA512_DIGEST_LEN: usize = 64;

/// Byte length of an Ed25519 seed (32 bytes).
pub const ED25519_SEED_LEN: usize = 32;

/// Byte length of an Ed25519 compressed public key (32 bytes).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Byte length of an Ed25519 signature (64 bytes).
pub const ED25519_SIGNATURE_LEN: usize = 64;

// ─── SHA-512 block-layout constants ──────────────────────────────────────────

/// Byte length of a domain-separation prefix within a fixed seed-chain block.
///
/// Each SHA-512 block in the seed chain is structured as
/// `domain[0..32] || payload[0..32] || SHA-512 padding`.
/// This constant names the domain portion's length.
pub const DOMAIN_LEN: usize = 32;

/// Total byte length of the message before padding (`domain || payload`).
///
/// Equals `DOMAIN_LEN + ED25519_SEED_LEN` = 64 bytes.
pub const FIXED_MESSAGE_LEN: usize = DOMAIN_LEN + ED25519_SEED_LEN;

/// Number of 64-bit words in a single 128-byte SHA-512 input block (= 16).
pub const FIXED_BLOCK_WORDS: usize = 16;

/// Word index within the block where the 32-byte payload begins.
///
/// The payload (seed or sk_seed) is stored as four 64-bit words at positions
/// 4..7 of the block word array (bytes 32..63).
pub const PAYLOAD_WORD_START: usize = 4;

/// Number of 64-bit words occupied by the 32-byte payload (= 4).
pub const PAYLOAD_WORD_COUNT: usize = 4;

/// Word index of the SHA-512 message-length field within the fixed block.
///
/// SHA-512 padding places the 64-bit big-endian bit-length in the last word
/// of the 128-byte block (word index 15, bytes 120..127).
pub const LENGTH_WORD_INDEX: usize = 15;

// ─── Domain-separation labels ─────────────────────────────────────────────────

/// Domain prefix used when hashing the seed to produce `commit_of_seed`.
const COMMIT_OF_SEED_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/commit/v1");

/// Domain prefix used in the PRF step that derives `sk_seed` from the seed.
const DERIVE_SK_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/derive-sk/v1");

/// Domain prefix used when hashing `sk_seed` to produce `hash_of_sk`.
const HASH_OF_SK_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/hash-sk/v1");

/// Domain prefix for the authentication transcript signed by the derived key.
const AUTH_TRANSCRIPT_DOMAIN: &[u8] = b"ed25519-pokos/auth-transcript/v1";

/// Magic bytes at the start of a serialized [`SeedChainProofEnvelope`].
///
/// "EPKOS001" — Ed25519 POKOS format version 1.
const PROOF_FORMAT_MAGIC: &[u8; 8] = b"EPKOS001";

pub mod private_seed_chain;
pub mod prover;
mod sha512;
pub mod verifier;

// ─── Type aliases ─────────────────────────────────────────────────────────────

/// A 32-byte Ed25519 seed.
pub type Seed = [u8; ED25519_SEED_LEN];

/// A 64-byte SHA-512 digest.
pub type DigestBytes = [u8; SHA512_DIGEST_LEN];

/// A SHA-512 digest of a seed, used as the public commitment.
///
/// Computed as `SHA512(COMMIT_OF_SEED_DOMAIN || seed)`.
pub type CommitOfSeedDigest = DigestBytes;

/// A SHA-512 digest of a derived Ed25519 secret key seed.
///
/// Computed as `SHA512(HASH_OF_SK_DOMAIN || sk_seed)`.
pub type HashOfSkDigest = DigestBytes;

// ─── Public types ─────────────────────────────────────────────────────────────

/// The public statement proved by a [`SeedChainProofEnvelope`].
///
/// Both fields are SHA-512 digests that are computable from the private `seed`
/// alone.  Together they form the statement: "I know a seed such that
/// `commit_of_seed` and `hash_of_sk` were computed from it via the prescribed
/// derivation chain."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedChainStatement {
    /// `SHA512(COMMIT_OF_SEED_DOMAIN || seed)` — public commitment to the seed.
    pub commit_of_seed: CommitOfSeedDigest,
    /// `SHA512(HASH_OF_SK_DOMAIN || sk_seed)` — public commitment to the derived key.
    pub hash_of_sk: HashOfSkDigest,
}

/// All secret material derived from a seed during proof generation.
///
/// This struct is produced by [`derive_secret_key_material`] and is the
/// prover's private witness.  Fields are intentionally not `Copy` or
/// `zeroize`d here — callers are responsible for handling them with
/// appropriate care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedSecretKeyMaterial {
    /// Full output of `SHA512(DERIVE_SK_DOMAIN || seed)`.  The first 32 bytes
    /// become `sk_seed`; the remaining 32 bytes are currently unused.
    pub prf_output: DigestBytes,
    /// First 32 bytes of `prf_output`, used as the Ed25519 signing seed.
    pub sk_seed: Seed,
    /// `SHA512(HASH_OF_SK_DOMAIN || sk_seed)` — the `hash_of_sk` public value.
    pub hash_of_sk: DigestBytes,
    /// Ed25519 verification key (public key) derived from `sk_seed`.
    pub authentication_key: VerificationKeyBytes,
}

/// A sealed (serialized) Plonky3 STARK proof for the three-segment SHA-512 chain.
///
/// The `sealed_proof` bytes are the full STARK proof bundle produced by the
/// Plonky3 prover.  The format is internal to this crate; use
/// [`serialize_proof`] / [`deserialize_proof`] to transport the outer envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512ProofBundle {
    /// Raw bytes of the serialized Plonky3 STARK proof.
    pub sealed_proof: Vec<u8>,
}

/// A complete, self-contained proof envelope for the POKOS statement.
///
/// This type bundles all three components a verifier needs:
/// 1. The public statement (`commit_of_seed`, `hash_of_sk`).
/// 2. The STARK proof that the statement was honestly derived from some hidden seed.
/// 3. An Ed25519 signature from the derived key, binding the proof to the key owner.
///
/// Use [`gen_pokos`] to produce an envelope and [`verify_pokos`] to check it.
/// For wire transport, see [`serialize_proof`] and [`deserialize_proof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedChainProofEnvelope {
    /// The public outputs of the seed-chain derivation.
    pub statement: SeedChainStatement,
    /// The STARK proof for the three SHA-512 steps in the derivation chain.
    pub sha512_proof: Sha512ProofBundle,
    /// Ed25519 verification key corresponding to the signing key derived from `sk_seed`.
    pub authentication_key: VerificationKeyBytes,
    /// Ed25519 signature over the `authentication_transcript` of `statement`,
    /// produced by the signing key derived from `sk_seed`.
    pub authentication_signature: Signature,
}

/// Errors returned by [`verify_pokos`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The STARK proof for the SHA-512 seed-chain is invalid or does not match
    /// the public statement.
    InvalidSkDerivationProof,
    /// The Ed25519 signature over the proof transcript is invalid.  Either the
    /// signature bytes are malformed or the signature was made with a different key.
    AuthenticationSignatureInvalid,
}

/// Errors returned by [`deserialize_proof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeserializeError {
    /// The byte slice ends before all expected fields have been read.
    Truncated,
    /// The leading magic bytes do not match `PROOF_FORMAT_MAGIC`.
    InvalidMagic,
    /// The Ed25519 signature bytes are structurally invalid.
    InvalidSignature,
    /// The byte slice contains extra data after the last expected field.
    TrailingBytes,
}

pub use prover::{commit_of_seed, derive_secret_key_material, gen_pokos, statement_from_seed};
pub use verifier::{deserialize_proof, serialize_proof, verify_pokos};

// ─── Crate-internal helpers ───────────────────────────────────────────────────

/// Computes a raw SHA-512 digest of `message`.
fn sha512(message: &[u8]) -> DigestBytes {
    let digest = Sha512::digest(message);
    let mut bytes = [0_u8; SHA512_DIGEST_LEN];
    bytes.copy_from_slice(&digest);
    bytes
}

/// Pads a byte-string label to a 32-byte domain-separation prefix.
///
/// Copies `label` into the first `label.len()` bytes of a zero-filled
/// `[u8; 32]`.  Panics at compile time if `label.len() > 32`.
const fn domain32(label: &[u8]) -> [u8; DOMAIN_LEN] {
    let mut out = [0_u8; DOMAIN_LEN];
    let mut i = 0;
    while i < label.len() {
        out[i] = label[i];
        i += 1;
    }
    out
}

/// Builds the single padded 128-byte SHA-512 block for a fixed-layout seed-chain segment.
///
/// The block layout is:
/// ```text
/// [domain: 32 bytes] [payload: 32 bytes] [0x80] [zeros] [bit_length: 8 bytes]
/// ```
/// `payload` must be exactly [`ED25519_SEED_LEN`] (32) bytes.
///
/// The resulting block is a valid, fully padded SHA-512 message that fits in
/// exactly one block, which is the structural invariant the AIR relies on.
pub(crate) fn fixed_single_block(domain: &[u8; DOMAIN_LEN], payload: &[u8]) -> [u8; 128] {
    assert_eq!(
        payload.len(),
        ED25519_SEED_LEN,
        "fixed seed-chain block expects a 32-byte payload"
    );

    let mut block = [0_u8; 128];
    block[..DOMAIN_LEN].copy_from_slice(domain);
    block[DOMAIN_LEN..FIXED_MESSAGE_LEN].copy_from_slice(payload);
    block[FIXED_MESSAGE_LEN] = 0x80;
    block[120..128].copy_from_slice(&((FIXED_MESSAGE_LEN as u64) * 8).to_be_bytes());
    block
}

/// Parses a 128-byte SHA-512 block into 16 big-endian 64-bit words.
pub(crate) fn block_words(block: [u8; 128]) -> [u64; FIXED_BLOCK_WORDS] {
    let mut words = [0_u64; FIXED_BLOCK_WORDS];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        words[i] = u64::from_be_bytes(chunk.try_into().expect("chunk size"));
    }
    words
}

/// Concatenates a 32-byte domain prefix and an arbitrary payload into one message.
///
/// Used by the prover to form the input to each domain-separated SHA-512 call
/// before passing it to the standard `sha2` crate (outside the circuit).
pub(crate) fn encode_domain_message(domain: &[u8; DOMAIN_LEN], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(FIXED_MESSAGE_LEN);
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    message
}

/// Builds the transcript that the authentication signature covers.
///
/// Layout:
/// ```text
/// AUTH_TRANSCRIPT_DOMAIN || 0x00 || commit_of_seed[64] || hash_of_sk[64]
/// ```
/// The `0x00` byte acts as a length delimiter between the domain string
/// and the two fixed-length fields.
pub(crate) fn authentication_transcript(statement: SeedChainStatement) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(AUTH_TRANSCRIPT_DOMAIN.len() + 1 + SHA512_DIGEST_LEN * 2);
    transcript.extend_from_slice(AUTH_TRANSCRIPT_DOMAIN);
    transcript.push(0);
    transcript.extend_from_slice(&statement.commit_of_seed);
    transcript.extend_from_slice(&statement.hash_of_sk);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed() -> Seed {
        [7_u8; ED25519_SEED_LEN]
    }

    #[test]
    fn round_trip_proof_verifies() {
        let proof = gen_pokos(sample_seed()).unwrap();

        assert_eq!(verify_pokos(&proof), Ok(()));
    }

    #[test]
    fn proof_serialization_round_trip() {
        let proof = gen_pokos(sample_seed()).unwrap();
        let encoded = serialize_proof(&proof);
        let decoded = deserialize_proof(&encoded).unwrap();

        assert_eq!(decoded, proof);
        assert_eq!(verify_pokos(&decoded), Ok(()));
    }

    #[test]
    fn rejects_wrong_commitment() {
        let mut proof = gen_pokos(sample_seed()).unwrap();
        proof.statement.commit_of_seed[0] ^= 1;

        assert_eq!(
            verify_pokos(&proof),
            Err(VerifyError::InvalidSkDerivationProof)
        );
    }

    #[test]
    fn rejects_wrong_authentication_key() {
        let mut proof = gen_pokos(sample_seed()).unwrap();
        let other_seed = [9_u8; ED25519_SEED_LEN];
        proof.authentication_key = derive_secret_key_material(other_seed).authentication_key;

        assert_eq!(
            verify_pokos(&proof),
            Err(VerifyError::AuthenticationSignatureInvalid)
        );
    }

    #[test]
    fn rejects_tampered_sha512_proof() {
        let mut proof = gen_pokos(sample_seed()).unwrap();
        proof.sha512_proof.sealed_proof[0] ^= 1;

        assert_eq!(
            verify_pokos(&proof),
            Err(VerifyError::InvalidSkDerivationProof)
        );
    }

    #[test]
    fn active_path_depends_only_on_sealed_proof() {
        let proof = gen_pokos(sample_seed()).unwrap();
        let encoded = serialize_proof(&proof);
        let decoded = deserialize_proof(&encoded).unwrap();

        assert_eq!(verify_pokos(&decoded), Ok(()));
    }

    #[test]
    fn rejects_broken_signature() {
        let mut proof = gen_pokos(sample_seed()).unwrap();
        let mut sig_bytes = proof.authentication_signature.to_bytes();
        sig_bytes[0] ^= 1;
        proof.authentication_signature = Signature::from_slice(&sig_bytes).unwrap();

        assert_eq!(
            verify_pokos(&proof),
            Err(VerifyError::AuthenticationSignatureInvalid)
        );
    }

    #[test]
    fn rejects_invalid_serialized_magic() {
        let proof = gen_pokos(sample_seed()).unwrap();
        let mut encoded = serialize_proof(&proof);
        encoded[0] ^= 1;

        assert_eq!(
            deserialize_proof(&encoded),
            Err(DeserializeError::InvalidMagic)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let proof = gen_pokos(sample_seed()).unwrap();
        let mut encoded = serialize_proof(&proof);
        encoded.push(0);

        assert_eq!(
            deserialize_proof(&encoded),
            Err(DeserializeError::TrailingBytes)
        );
    }

    #[test]
    fn rejects_overflowing_sha512_bundle_length() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PROOF_FORMAT_MAGIC);
        encoded.extend_from_slice(&[0_u8; SHA512_DIGEST_LEN]);
        encoded.extend_from_slice(&[0_u8; SHA512_DIGEST_LEN]);
        encoded.extend_from_slice(&u64::MAX.to_be_bytes());

        assert_eq!(
            deserialize_proof(&encoded),
            Err(DeserializeError::Truncated)
        );
    }

    #[test]
    fn fixed_block_layout_is_stable() {
        let seed = sample_seed();
        let block = fixed_single_block(&COMMIT_OF_SEED_DOMAIN, &seed);
        let words = block_words(block);

        let mut expected_word = [0_u8; 8];
        expected_word.copy_from_slice(&COMMIT_OF_SEED_DOMAIN[..8]);
        assert_eq!(words[0], u64::from_be_bytes(expected_word));

        let payload_words = &words[PAYLOAD_WORD_START..PAYLOAD_WORD_START + PAYLOAD_WORD_COUNT];
        for (i, word) in payload_words.iter().enumerate() {
            let mut expected = [0_u8; 8];
            expected.copy_from_slice(&seed[i * 8..(i + 1) * 8]);
            assert_eq!(*word, u64::from_be_bytes(expected));
        }

        assert_eq!(words[8], 0x8000_0000_0000_0000);
        assert_eq!(words[LENGTH_WORD_INDEX], (FIXED_MESSAGE_LEN as u64) * 8);
    }
}
