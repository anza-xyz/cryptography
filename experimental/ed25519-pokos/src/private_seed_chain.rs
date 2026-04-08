//! Public types and helpers describing the three-segment SHA-512 seed chain.
//!
//! The seed chain is the computation proved by the STARK:
//!
//! ```text
//! Segment 0 (Commit):  SHA512(COMMIT_OF_SEED_DOMAIN  || seed)    → commit_of_seed
//! Segment 1 (Derive):  SHA512(DERIVE_SK_DOMAIN       || seed)    → prf_output (sk_seed = prf_output[0..32])
//! Segment 2 (HashSk):  SHA512(HASH_OF_SK_DOMAIN      || sk_seed) → hash_of_sk
//! ```
//!
//! Each segment is a single-block SHA-512 evaluation with the same fixed layout:
//! 32 bytes of domain label followed by 32 bytes of payload, padded to 128 bytes.
//!
//! The types in this module describe this layout at the *witness* level (before the
//! STARK circuit is involved).  They are shared with the inner
//! `sha512/private_seed_chain.rs` STARK layer (which re-exports
//! [`PrivateSeedChainPublic`] and imports [`PrivateSeedChainWitness`] and
//! [`segment_block`] from here) so that each type is defined in exactly one place.

use crate::{
    COMMIT_OF_SEED_DOMAIN, DERIVE_SK_DOMAIN, DOMAIN_LEN, DigestBytes, FIXED_BLOCK_WORDS,
    FIXED_MESSAGE_LEN, HASH_OF_SK_DOMAIN, PAYLOAD_WORD_COUNT, PAYLOAD_WORD_START, Seed,
    block_words, fixed_single_block, sha512,
};

/// Number of real SHA-512 segments in the seed chain (commit, derive, hash_sk).
pub const ACTIVE_SEGMENT_COUNT: usize = 3;

/// Number of segments after padding to the next power of two for the AIR.
pub const ACTIVE_PADDED_SEGMENT_COUNT: usize = ACTIVE_SEGMENT_COUNT.next_power_of_two();

/// Total number of AIR trace rows for the padded seed chain
/// (`ACTIVE_PADDED_SEGMENT_COUNT × 128`).
pub const ACTIVE_AIR_TRACE_ROWS: usize = 128 * ACTIVE_PADDED_SEGMENT_COUNT;

/// Number of columns in the AIR trace.
pub const ACTIVE_AIR_TRACE_COLS: usize = 1076;

/// Identifies which of the three seed-chain segments a layout or constraint belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    /// The commit segment: `SHA512(COMMIT_OF_SEED_DOMAIN || seed)`.
    Commit,
    /// The derive segment: `SHA512(DERIVE_SK_DOMAIN || seed)`.
    Derive,
    /// The hash-of-sk segment: `SHA512(HASH_OF_SK_DOMAIN || sk_seed)`.
    HashSk,
}

/// The prover's private witness for the seed chain.
///
/// Both fields are secret; only the public outputs derived from them are
/// exposed in the [`SeedChainStatement`](crate::SeedChainStatement).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSeedChainWitness {
    /// The original 32-byte secret seed.
    pub seed: Seed,
    /// The first 32 bytes of `SHA512(DERIVE_SK_DOMAIN || seed)`, used as the
    /// Ed25519 signing seed.
    pub sk_seed: Seed,
}

/// The public outputs of the seed chain, visible to the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSeedChainPublic {
    /// `SHA512(COMMIT_OF_SEED_DOMAIN || seed)`.
    pub commit_of_seed: DigestBytes,
    /// `SHA512(HASH_OF_SK_DOMAIN || sk_seed)`.
    pub hash_of_sk: DigestBytes,
}

/// The fully expanded block layout for a single seed-chain segment.
///
/// This captures both the domain/payload metadata and the concrete word
/// decomposition used by the AIR trace builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedSegmentLayout {
    /// Which segment this layout corresponds to.
    pub kind: SegmentKind,
    /// The 32-byte domain-separation prefix for this segment.
    pub domain: [u8; DOMAIN_LEN],
    /// The four 64-bit words of the 32-byte payload (words 4..7 of the block).
    pub payload_words: [u64; PAYLOAD_WORD_COUNT],
    /// All 16 big-endian 64-bit words of the full padded 128-byte block.
    pub block_words: [u64; FIXED_BLOCK_WORDS],
}

/// Computes the public outputs from a private witness without running the STARK.
///
/// Useful for tests and for building the expected public values before proof
/// generation or verification.
pub fn public_from_witness(witness: PrivateSeedChainWitness) -> PrivateSeedChainPublic {
    PrivateSeedChainPublic {
        commit_of_seed: sha512(&segment_message(SegmentKind::Commit, witness.seed)),
        hash_of_sk: sha512(&segment_message(SegmentKind::HashSk, witness.sk_seed)),
    }
}

/// Builds the single padded 128-byte SHA-512 block for a segment payload.
///
/// This is the exact fixed-layout block consumed by the SHA-512 AIR:
/// 32 bytes of domain, 32 bytes of payload, then standard single-block SHA-512
/// padding out to 128 bytes.
pub fn segment_block(kind: SegmentKind, payload: Seed) -> [u8; 128] {
    fixed_single_block(&segment_domain(kind), &payload)
}

/// Builds the full [`FixedSegmentLayout`] for a given segment kind and payload.
///
/// Computes the padded 128-byte block, then extracts the 16 block words and
/// the 4 payload words from it.
pub fn segment_layout(kind: SegmentKind, payload: Seed) -> FixedSegmentLayout {
    let block = segment_block(kind, payload);
    let block_words = block_words(block);
    let payload_words = core::array::from_fn(|i| block_words[PAYLOAD_WORD_START + i]);
    FixedSegmentLayout {
        kind,
        domain: segment_domain(kind),
        payload_words,
        block_words,
    }
}

/// Builds the 64-byte pre-padding message `domain || payload` for a segment.
pub fn segment_message(kind: SegmentKind, payload: Seed) -> [u8; FIXED_MESSAGE_LEN] {
    let mut message = [0_u8; FIXED_MESSAGE_LEN];
    message[..DOMAIN_LEN].copy_from_slice(&segment_domain(kind));
    message[DOMAIN_LEN..].copy_from_slice(&payload);
    message
}

/// Returns the 32-byte domain-separation prefix for `kind`.
pub fn segment_domain(kind: SegmentKind) -> [u8; DOMAIN_LEN] {
    match kind {
        SegmentKind::Commit => COMMIT_OF_SEED_DOMAIN,
        SegmentKind::Derive => DERIVE_SK_DOMAIN,
        SegmentKind::HashSk => HASH_OF_SK_DOMAIN,
    }
}

/// Encodes a 32-byte `payload` as four 64-bit big-endian words.
///
/// These are words 4..7 of the SHA-512 input block — the words the AIR
/// treats as the private payload.
pub fn payload_words(payload: Seed) -> [u64; PAYLOAD_WORD_COUNT] {
    core::array::from_fn(|i| {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&payload[i * 8..(i + 1) * 8]);
        u64::from_be_bytes(bytes)
    })
}

/// Returns the SHA-512 message-length word for the fixed 64-byte message.
///
/// SHA-512 encodes the bit-length of the original message in the last word of
/// the padded block.  For a 64-byte message this is `64 × 8 = 512`.
pub fn length_word() -> u64 {
    (FIXED_MESSAGE_LEN as u64) * 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ED25519_SEED_LEN, FIXED_BLOCK_WORDS, LENGTH_WORD_INDEX, derive_secret_key_material,
    };

    fn sample_seed() -> Seed {
        [7_u8; ED25519_SEED_LEN]
    }

    #[test]
    fn segment_layout_payload_words_are_stable() {
        let seed = sample_seed();
        let layout = segment_layout(SegmentKind::Commit, seed);

        assert_eq!(layout.payload_words, payload_words(seed));
        assert_eq!(layout.block_words[LENGTH_WORD_INDEX], length_word());
    }

    #[test]
    fn public_outputs_match_existing_derivation() {
        let seed = sample_seed();
        let derived = derive_secret_key_material(seed);
        let witness = PrivateSeedChainWitness {
            seed,
            sk_seed: derived.sk_seed,
        };
        let public = public_from_witness(witness);

        assert_eq!(public.commit_of_seed, crate::commit_of_seed(seed));
        assert_eq!(public.hash_of_sk, derived.hash_of_sk);
    }

    #[test]
    fn all_segments_share_fixed_block_shape() {
        let seed = sample_seed();
        let derived = derive_secret_key_material(seed);
        let layouts = [
            segment_layout(SegmentKind::Commit, seed),
            segment_layout(SegmentKind::Derive, seed),
            segment_layout(SegmentKind::HashSk, derived.sk_seed),
        ];

        for layout in layouts {
            assert_eq!(layout.block_words.len(), FIXED_BLOCK_WORDS);
            assert_eq!(layout.block_words[LENGTH_WORD_INDEX], length_word());
            assert_eq!(layout.block_words[8], 0x8000_0000_0000_0000);
        }
    }
}
