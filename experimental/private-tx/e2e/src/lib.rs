//! Loads the circuit fixtures under `../fixtures/` and converts them to the
//! verifier program's on-chain format.
//!
//! Each fixture directory holds gnark's native encodings (`vk.bin`,
//! `proof.bin`, `public.bin`) written by `privtx`, plus any circuit-specific
//! witness file. The note commitment, nullifier and Merkle tree are
//! recomputed here with light-poseidon so every in-circuit hash is checked
//! against the Poseidon the Solana syscall implements.

pub mod curve;
pub mod encrypt;

use {
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
    groth16_convert::{arkworks, gnark, OnChainKey, OnChainProof},
    light_poseidon::{Poseidon, PoseidonHasher},
    std::path::PathBuf,
};

/// Path of `<fixture>/<name>`.
pub fn fixture_path(fixture: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(fixture)
        .join(name)
}

/// Reads `<fixture>/<name>`, panicking with the path on failure.
pub fn read_fixture(fixture: &str, name: &str) -> Vec<u8> {
    let path = fixture_path(fixture, name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A proof and key in on-chain form, with public inputs as 32-byte big-endian
/// canonical scalars in circuit order.
pub struct Groth16Fixture {
    pub key: OnChainKey,
    pub proof: OnChainProof,
    pub public_inputs: Vec<[u8; 32]>,
}

/// Parses and converts `vk.bin`, `proof.bin`, `public.bin`.
pub fn load_groth16(fixture: &str) -> Groth16Fixture {
    load_groth16_files(fixture, "vk.bin", "proof.bin", "public.bin")
}

/// Parses and converts a key, proof and public witness by file name under
/// `<fixture>/`, for fixtures holding several proofs of one key.
pub fn load_groth16_files(fixture: &str, vk: &str, proof: &str, public: &str) -> Groth16Fixture {
    let key = gnark::parse_verifying_key(&read_fixture(fixture, vk)).expect(vk);
    let proof = gnark::parse_proof(&read_fixture(fixture, proof)).expect(proof);
    let inputs = gnark::parse_public_witness(&read_fixture(fixture, public)).expect(public);
    Groth16Fixture {
        key,
        proof,
        public_inputs: arkworks::public_inputs(&inputs),
    }
}

/// Circom-parameter Poseidon of 1..12 field elements, via light-poseidon: the
/// reference the Solana `sol_poseidon` syscall and `syscall/bn254-backend`
/// derive their constants from. Circuits that hash in-circuit are checked
/// against this.
pub fn poseidon(inputs: &[Fr]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("supported width");
    fr_to_bytes(&hasher.hash(inputs).expect("hash"))
}

/// A Poseidon domain tag (`circuits/domain`): the name's ASCII bytes as a
/// big-endian field element.
pub fn domain_tag(name: &str) -> Fr {
    Fr::from_be_bytes_mod_order(name.as_bytes())
}

/// Decodes a 0x-prefixed big-endian 32-byte hex string.
pub fn bytes_from_hex(s: &str) -> [u8; 32] {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex");
    raw.try_into().expect("32 bytes")
}

/// Decodes a canonical field element from 0x-prefixed big-endian hex.
pub fn fr_from_hex(s: &str) -> Fr {
    let bytes = bytes_from_hex(s);
    let e = Fr::from_be_bytes_mod_order(&bytes);
    assert_eq!(fr_to_bytes(&e), bytes, "non-canonical field element {s}");
    e
}

/// Big-endian canonical encoding, as the verifier expects public inputs.
pub fn fr_to_bytes(e: &Fr) -> [u8; 32] {
    e.into_bigint().to_bytes_be().try_into().unwrap()
}

/// `value` as a 32-byte big-endian scalar.
pub fn u64_to_bytes(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// The opened note behind the mint fixture (`note.json`), as written by
/// `privtx mint-fixture`: field elements are 0x-prefixed big-endian hex.
/// The note is `(value, d, pk_d, r)` with `g_d = GroupHash(d)` written out
/// so the commitment can be recomputed without the group hash.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NoteOpening {
    pub value: u64,
    pub d: String,
    pub g_d_x: String,
    pub g_d_y: String,
    pub pk_d_x: String,
    pub pk_d_y: String,
    pub r: String,
    pub commitment: String,
}

/// `note.json` of the mint fixture: the note, both ciphertexts, the hashes.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MintFixture {
    pub note: NoteOpening,
    pub audit_pk_x: String,
    pub audit_pk_y: String,
    pub audit_blob: String,
    pub enc_blob: String,
    pub audit_hash: String,
    pub enc_hash: String,
}

impl MintFixture {
    pub fn load(fixture: &str) -> Self {
        serde_json::from_slice(&read_fixture(fixture, "note.json")).expect("note.json")
    }

    pub fn audit_pk(&self) -> curve::Point {
        curve::Point {
            x: fr_from_hex(&self.audit_pk_x),
            y: fr_from_hex(&self.audit_pk_y),
        }
    }
}

/// Decodes 0x-prefixed hex of any length.
pub fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex")
}

impl NoteOpening {
    /// `Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r)` under the
    /// circom parameters.
    pub fn poseidon_commitment(&self) -> [u8; 32] {
        poseidon(&[
            domain_tag("privtx/cm"),
            Fr::from(self.value),
            fr_from_hex(&self.g_d_x),
            fr_from_hex(&self.g_d_y),
            fr_from_hex(&self.pk_d_x),
            fr_from_hex(&self.pk_d_y),
            fr_from_hex(&self.r),
        ])
    }

    pub fn commitment_bytes(&self) -> [u8; 32] {
        bytes_from_hex(&self.commitment)
    }
}

/// `Poseidon(NF, nk, cm, index)`, the nullifier of the note with commitment
/// `cm` at leaf `index`, for the holder of nullifier key `nk`.
pub fn nullifier(nk: &[u8; 32], cm: &[u8; 32], index: u64) -> [u8; 32] {
    poseidon(&[
        domain_tag("privtx/nf"),
        Fr::from_be_bytes_mod_order(nk),
        Fr::from_be_bytes_mod_order(cm),
        Fr::from(index),
    ])
}

/// The burn sighash, `circuits/burn.SigHash`: addresses as two 128-bit
/// big-endian halves each.
pub fn burn_sighash(
    pool: &[u8; 32],
    destination: &[u8; 32],
    nullifier: &[u8; 32],
    value: u64,
) -> [u8; 32] {
    let half = |b: &[u8]| Fr::from_be_bytes_mod_order(b);
    poseidon(&[
        domain_tag("privtx/sighash"),
        half(&pool[..16]),
        half(&pool[16..]),
        half(&destination[..16]),
        half(&destination[16..]),
        Fr::from_be_bytes_mod_order(nullifier),
        Fr::from(value),
    ])
}

/// Root of the commitment tree holding `leaves` (in order) at `depth`: binary,
/// `Poseidon(NODE, left, right)` nodes, empty leaf 0 and empty subtrees hashed
/// up from it. Mirrors `circuits/merkle`.
pub fn merkle_root(leaves: &[Fr], depth: usize) -> [u8; 32] {
    let levels = merkle_levels(leaves, depth);
    let mut empty = Fr::from(0u64);
    for _ in 0..depth {
        empty = hash2(empty, empty);
    }
    fr_to_bytes(&levels[depth].first().copied().unwrap_or(empty))
}

/// Every level of the occupied part of the tree, leaves first; positions
/// past a level's length are the empty subtree of that height.
pub fn merkle_levels(leaves: &[Fr], depth: usize) -> Vec<Vec<Fr>> {
    let mut levels = vec![leaves.to_vec()];
    let mut empty = Fr::from(0u64);
    for _ in 0..depth {
        let cur = levels.last().unwrap();
        let next: Vec<Fr> = cur
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).copied().unwrap_or(empty);
                hash2(pair[0], right)
            })
            .collect();
        levels.push(next);
        empty = hash2(empty, empty);
    }
    levels
}

/// `Poseidon(NODE, a, b)`, the tree's node hash.
pub fn hash2(a: Fr, b: Fr) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(3).expect("width 4");
    hasher
        .hash(&[domain_tag("privtx/node"), a, b])
        .expect("hash")
}

/// The burn fixture's witness (`burn.json`), as written by
/// `privtx burn-fixture`: the tree's leaves in order, the burned note and its
/// index, the root and nullifier the circuit published, and whether it was a
/// forced burn (forfeiture) or the owner's unshield.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BurnFixture {
    pub depth: usize,
    pub leaves: Vec<String>,
    pub index: u64,
    pub note: NoteOpening,
    pub root: String,
    pub nullifier: String,
    pub forced: bool,
    pub nk: String,
    pub pool: String,
    pub destination: String,
    pub sighash: String,
}

impl BurnFixture {
    pub fn load(fixture: &str) -> Self {
        serde_json::from_slice(&read_fixture(fixture, "burn.json")).expect("burn.json")
    }

    /// The tree root recomputed from the leaves.
    pub fn poseidon_root(&self) -> [u8; 32] {
        let leaves: Vec<Fr> = self.leaves.iter().map(|l| fr_from_hex(l)).collect();
        merkle_root(&leaves, self.depth)
    }

    /// The nullifier recomputed from nk, the commitment and the leaf index.
    pub fn poseidon_nullifier(&self) -> [u8; 32] {
        nullifier(
            &bytes_from_hex(&self.nk),
            &self.note.commitment_bytes(),
            self.index,
        )
    }

    /// The sighash recomputed from pool, destination, nullifier and value.
    pub fn poseidon_sighash(&self) -> [u8; 32] {
        burn_sighash(
            &bytes_from_hex(&self.pool),
            &bytes_from_hex(&self.destination),
            &bytes_from_hex(&self.nullifier),
            self.note.value,
        )
    }
}
