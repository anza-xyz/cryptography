//! Active protocol shape:
//! - one SHA-512 STARK proves `commit_of_seed`, `seed -> sk_seed`, and `hash_of_sk`
//! - the STARK verifier only sees the public statement `(commit_of_seed, hash_of_sk)`
//! - Ed25519 is only used outside the circuit to authenticate the proof envelope

use curve25519::ed_sigs::{Signature, VerificationKeyBytes};
use sha2::{Digest, Sha512};
use sha512::{prove_private_seed_chain, verify_private_seed_chain_statement};

pub const SHA512_DIGEST_LEN: usize = 64;
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const DOMAIN_LEN: usize = 32;
pub const FIXED_MESSAGE_LEN: usize = DOMAIN_LEN + ED25519_SEED_LEN;
pub const FIXED_BLOCK_WORDS: usize = 16;
pub const PAYLOAD_WORD_START: usize = 4;
pub const PAYLOAD_WORD_COUNT: usize = 4;
pub const LENGTH_WORD_INDEX: usize = 15;

const COMMIT_OF_SEED_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/commit/v1");
const DERIVE_SK_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/derive-sk/v1");
const HASH_OF_SK_DOMAIN: [u8; DOMAIN_LEN] = domain32(b"ed25519-pokos/hash-sk/v1");
const AUTH_TRANSCRIPT_DOMAIN: &[u8] = b"ed25519-pokos/auth-transcript/v1";
const PROOF_FORMAT_MAGIC: &[u8; 8] = b"EPKOS001";

pub mod private_seed_chain;
pub mod prover;
mod sha512;
pub mod verifier;

pub type Seed = [u8; ED25519_SEED_LEN];
pub type DigestBytes = [u8; SHA512_DIGEST_LEN];
pub type CommitOfSeedDigest = DigestBytes;
pub type HashOfSkDigest = DigestBytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedChainStatement {
    pub commit_of_seed: CommitOfSeedDigest,
    pub hash_of_sk: HashOfSkDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedSecretKeyMaterial {
    pub prf_output: DigestBytes,
    pub sk_seed: Seed,
    pub hash_of_sk: DigestBytes,
    pub authentication_key: VerificationKeyBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512ProofBundle {
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedChainProofEnvelope {
    pub statement: SeedChainStatement,
    pub sha512_proof: Sha512ProofBundle,
    pub authentication_key: VerificationKeyBytes,
    pub authentication_signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSkDerivationProof,
    AuthenticationSignatureInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeserializeError {
    Truncated,
    InvalidMagic,
    InvalidSignature,
    TrailingBytes,
}

pub fn commit_of_seed(seed: Seed) -> DigestBytes {
    prover::commit_of_seed(seed)
}

pub fn derive_secret_key_material(seed: Seed) -> DerivedSecretKeyMaterial {
    prover::derive_secret_key_material(seed)
}

pub fn statement_from_seed(seed: Seed) -> SeedChainStatement {
    prover::statement_from_seed(seed)
}

pub fn gen_pokos(seed: Seed) -> Result<SeedChainProofEnvelope, String> {
    prover::gen_pokos(seed)
}

pub fn verify_pokos(proof: &SeedChainProofEnvelope) -> Result<(), VerifyError> {
    verifier::verify_pokos(proof)
}

pub fn serialize_proof(proof: &SeedChainProofEnvelope) -> Vec<u8> {
    verifier::serialize_proof(proof)
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<SeedChainProofEnvelope, DeserializeError> {
    verifier::deserialize_proof(bytes)
}

fn sha512(message: &[u8]) -> DigestBytes {
    let digest = Sha512::digest(message);
    let mut bytes = [0_u8; SHA512_DIGEST_LEN];
    bytes.copy_from_slice(&digest);
    bytes
}

const fn domain32(label: &[u8]) -> [u8; DOMAIN_LEN] {
    let mut out = [0_u8; DOMAIN_LEN];
    let mut i = 0;
    while i < label.len() {
        out[i] = label[i];
        i += 1;
    }
    out
}

fn append_sha512_bundle(bytes: &mut Vec<u8>, bundle: &Sha512ProofBundle) {
    bytes.extend_from_slice(&(bundle.sealed_proof.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&bundle.sealed_proof);
}

fn read_sha512_bundle(cursor: &mut Cursor<'_>) -> Result<Sha512ProofBundle, DeserializeError> {
    let sealed_proof = cursor.read_vec()?;

    Ok(Sha512ProofBundle { sealed_proof })
}

fn prove_sha512_bundle(seed: Seed) -> Result<Sha512ProofBundle, String> {
    let sealed = prove_private_seed_chain(seed)?;
    Ok(Sha512ProofBundle {
        sealed_proof: sealed.sealed_proof,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BundleVerifyError {
    InvalidProof,
}

fn verify_sha512_bundle(
    bundle: &Sha512ProofBundle,
    statement: SeedChainStatement,
) -> Result<(), BundleVerifyError> {
    let verified = verify_private_seed_chain_statement(
        &sha512::SealedPrivateSeedChainProof {
            sealed_proof: bundle.sealed_proof.clone(),
        },
        sha512::PrivateSeedChainPublic {
            commit_of_seed: statement.commit_of_seed,
            hash_of_sk: statement.hash_of_sk,
        },
    );
    if !verified {
        return Err(BundleVerifyError::InvalidProof);
    }

    Ok(())
}

fn fixed_single_block(domain: &[u8; DOMAIN_LEN], payload: &[u8]) -> [u8; 128] {
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

pub(crate) fn block_words(block: [u8; 128]) -> [u64; FIXED_BLOCK_WORDS] {
    let mut words = [0_u64; FIXED_BLOCK_WORDS];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        words[i] = u64::from_be_bytes(chunk.try_into().expect("chunk size"));
    }
    words
}

fn encode_domain_message(domain: &[u8; DOMAIN_LEN], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(FIXED_MESSAGE_LEN);
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    message
}

fn authentication_transcript(statement: SeedChainStatement) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(AUTH_TRANSCRIPT_DOMAIN.len() + 1 + SHA512_DIGEST_LEN * 2);
    transcript.extend_from_slice(AUTH_TRANSCRIPT_DOMAIN);
    transcript.push(0);
    transcript.extend_from_slice(&statement.commit_of_seed);
    transcript.extend_from_slice(&statement.hash_of_sk);
    transcript
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, DeserializeError> {
        if self.offset + len > self.bytes.len() {
            return Err(DeserializeError::Truncated);
        }
        let slice = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializeError> {
        if self.offset + N > self.bytes.len() {
            return Err(DeserializeError::Truncated);
        }
        let mut out = [0_u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }

    fn read_u64(&mut self) -> Result<u64, DeserializeError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, DeserializeError> {
        let len = self.read_u64()? as usize;
        self.read_exact(len)
    }

    fn is_at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }
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
