//! The indexer and wallet side: rebuilds a pool's history from the
//! instructions submitted to it, exactly as an indexer would from
//! transaction history, and scans it for a wallet's notes.

use {
    crate::{
        domain_tag,
        encrypt::{decrypt_note, Note, RECIPIENT_BLOB_LEN},
        merkle_levels, poseidon,
    },
    ark_bn254::Fr,
    ark_ff::PrimeField,
    private_tx_pool::state::blob,
    solana_groth16_verify::constants::PROOF_SIZE,
    solana_instruction::Instruction,
};

/// A pool's history: leaves in order with their recipient blobs, and the
/// nullifiers published.
#[derive(Default, Debug, Clone)]
pub struct Indexer {
    pub leaves: Vec<[u8; 32]>,
    pub blobs: Vec<Vec<u8>>,
    pub nullifiers: Vec<[u8; 32]>,
}

impl Indexer {
    /// Reads a pool instruction and records what it published. Only
    /// instructions of the pool program are looked at; a failed one must
    /// not be passed.
    pub fn observe(&mut self, ix: &Instruction) {
        if ix.program_id != private_tx_pool::ID {
            return;
        }
        let d = &ix.data;
        let word = |o: usize| -> [u8; 32] { d[o..o + 32].try_into().unwrap() };
        match d[0] {
            1 => {
                // Mint: tag, proof, commitment, value, audit blob, recipient blob.
                let cm = word(1 + PROOF_SIZE);
                let blob = d[d.len() - RECIPIENT_BLOB_LEN..].to_vec();
                self.leaves.push(cm);
                self.blobs.push(blob);
            }
            2 => {
                // Burn: tag, proof, root, nullifier, ...
                self.nullifiers.push(word(1 + PROOF_SIZE + 32));
            }
            3 => {
                // Transfer: tag, proof, root slot, nf0, nf1, cm0, cm1, audit blob, enc blobs.
                let o = 1 + PROOF_SIZE + 1;
                self.nullifiers.push(word(o));
                self.nullifiers.push(word(o + 32));
                let blobs = &d[d.len() - 2 * blob::RECIPIENT_LEN..];
                for i in 0..2 {
                    self.leaves.push(word(o + 64 + 32 * i));
                    self.blobs.push(
                        blobs[i * blob::RECIPIENT_LEN..(i + 1) * blob::RECIPIENT_LEN].to_vec(),
                    );
                }
            }
            _ => {}
        }
    }

    fn frs(&self) -> Vec<Fr> {
        self.leaves
            .iter()
            .map(|l| Fr::from_be_bytes_mod_order(l))
            .collect()
    }

    /// The current root of the rebuilt tree.
    pub fn root(&self, depth: usize) -> [u8; 32] {
        crate::merkle_root(&self.frs(), depth)
    }

    /// The Merkle siblings of leaf `index`, leaf level first.
    pub fn path(&self, depth: usize, index: u64) -> Vec<[u8; 32]> {
        let levels = merkle_levels(&self.frs(), depth);
        let mut zero = Fr::from(0u64);
        let mut out = Vec::with_capacity(depth);
        for (h, level) in levels.iter().enumerate().take(depth) {
            let sib = ((index >> h) ^ 1) as usize;
            out.push(crate::fr_to_bytes(level.get(sib).unwrap_or(&zero)));
            zero = crate::hash2(zero, zero);
        }
        out
    }
}

/// A note the wallet can spend.
#[derive(Debug, Clone, Copy)]
pub struct Owned {
    pub index: u64,
    pub note: Note,
}

/// A wallet's viewing side: incoming viewing key and nullifier key.
pub struct Wallet {
    pub ivk: Fr,
    pub nk: Fr,
}

impl Wallet {
    /// `Poseidon(NF, nk, cm, index)`.
    pub fn nullifier(&self, cm: &[u8; 32], index: u64) -> [u8; 32] {
        poseidon(&[
            domain_tag("privtx/nf"),
            self.nk,
            Fr::from_be_bytes_mod_order(cm),
            Fr::from(index),
        ])
    }

    /// Trial-decrypts every leaf's blob and returns the unspent notes.
    pub fn scan(&self, idx: &Indexer) -> Vec<Owned> {
        let mut owned = Vec::new();
        for (i, (cm, blob)) in idx.leaves.iter().zip(&idx.blobs).enumerate() {
            let Some(note) = decrypt_note(&self.ivk, blob, cm) else {
                continue;
            };
            if idx.nullifiers.contains(&self.nullifier(cm, i as u64)) {
                continue;
            }
            owned.push(Owned {
                index: i as u64,
                note,
            });
        }
        owned
    }
}
