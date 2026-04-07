use crate::{
    COMMIT_OF_SEED_DOMAIN, DERIVE_SK_DOMAIN, DOMAIN_LEN, DigestBytes, FIXED_BLOCK_WORDS,
    FIXED_MESSAGE_LEN, HASH_OF_SK_DOMAIN, PAYLOAD_WORD_COUNT, PAYLOAD_WORD_START, Seed,
    block_words, fixed_single_block, sha512,
};

pub const ACTIVE_SEGMENT_COUNT: usize = 3;
pub const ACTIVE_PADDED_SEGMENT_COUNT: usize = ACTIVE_SEGMENT_COUNT.next_power_of_two();
pub const ACTIVE_AIR_TRACE_ROWS: usize = 128 * ACTIVE_PADDED_SEGMENT_COUNT;
pub const ACTIVE_AIR_TRACE_COLS: usize = 1076;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    Commit,
    Derive,
    HashSk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSeedChainWitness {
    pub seed: Seed,
    pub sk_seed: Seed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSeedChainPublic {
    pub commit_of_seed: DigestBytes,
    pub hash_of_sk: DigestBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedSegmentLayout {
    pub kind: SegmentKind,
    pub domain: [u8; DOMAIN_LEN],
    pub payload_words: [u64; PAYLOAD_WORD_COUNT],
    pub block_words: [u64; FIXED_BLOCK_WORDS],
}

pub fn public_from_witness(witness: PrivateSeedChainWitness) -> PrivateSeedChainPublic {
    PrivateSeedChainPublic {
        commit_of_seed: sha512(&segment_message(SegmentKind::Commit, witness.seed)),
        hash_of_sk: sha512(&segment_message(SegmentKind::HashSk, witness.sk_seed)),
    }
}

pub fn segment_layout(kind: SegmentKind, payload: Seed) -> FixedSegmentLayout {
    let block = fixed_single_block(&segment_domain(kind), &payload);
    let block_words = block_words(block);
    let payload_words = core::array::from_fn(|i| block_words[PAYLOAD_WORD_START + i]);
    FixedSegmentLayout {
        kind,
        domain: segment_domain(kind),
        payload_words,
        block_words,
    }
}

pub fn segment_message(kind: SegmentKind, payload: Seed) -> [u8; FIXED_MESSAGE_LEN] {
    let mut message = [0_u8; FIXED_MESSAGE_LEN];
    message[..DOMAIN_LEN].copy_from_slice(&segment_domain(kind));
    message[DOMAIN_LEN..].copy_from_slice(&payload);
    message
}

pub fn segment_domain(kind: SegmentKind) -> [u8; DOMAIN_LEN] {
    match kind {
        SegmentKind::Commit => COMMIT_OF_SEED_DOMAIN,
        SegmentKind::Derive => DERIVE_SK_DOMAIN,
        SegmentKind::HashSk => HASH_OF_SK_DOMAIN,
    }
}

pub fn payload_words(payload: Seed) -> [u64; PAYLOAD_WORD_COUNT] {
    core::array::from_fn(|i| {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&payload[i * 8..(i + 1) * 8]);
        u64::from_be_bytes(bytes)
    })
}

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
