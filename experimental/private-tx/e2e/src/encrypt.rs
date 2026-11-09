//! Note decryption for the recipient and the custodian, and the hashes the
//! program recomputes over ciphertexts. Mirrors `circuits/encrypt`.

use {
    crate::{
        curve::{self, Point},
        domain_tag, fr_to_bytes, poseidon,
    },
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
};

/// Recipient blob: compressed epk ‖ 51-byte ciphertext.
pub const RECIPIENT_BLOB_LEN: usize = 32 + 8 + 11 + 32;
/// Ciphertext field elements per note in an audit blob.
pub const AUDIT_ELEMENTS: usize = 3;

/// An opened note, as decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    pub value: u64,
    pub d: [u8; 11],
    pub g_d: Point,
    pub pk_d: Point,
    pub r: Fr,
}

impl Note {
    /// `Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r)`.
    pub fn commitment(&self) -> [u8; 32] {
        poseidon(&[
            domain_tag("privtx/cm"),
            Fr::from(self.value),
            self.g_d.x,
            self.g_d.y,
            self.pk_d.x,
            self.pk_d.y,
            self.r,
        ])
    }
}

fn kdf(ss: &Point, epk: &Point) -> Fr {
    Fr::from_be_bytes_mod_order(&poseidon(&[
        domain_tag("privtx/kdf"),
        ss.x,
        ss.y,
        epk.x,
        epk.y,
    ]))
}

fn keystream(key: &Fr, i: u64) -> [u8; 32] {
    poseidon(&[domain_tag("privtx/enc"), *key, Fr::from(i)])
}

/// Trial-decrypts a recipient blob with `ivk` against the leaf `cm`.
pub fn decrypt_note(ivk: &Fr, blob: &[u8], cm: &[u8; 32]) -> Option<Note> {
    if blob.len() != RECIPIENT_BLOB_LEN {
        return None;
    }
    let epk = Point::decompress(blob[..32].try_into().unwrap())?;
    if !epk.is_on_curve() {
        return None;
    }
    let key = kdf(&epk.mul(ivk), &epk);
    let mut pt = [0u8; RECIPIENT_BLOB_LEN - 32];
    pt.copy_from_slice(&blob[32..]);
    // 31 bytes per keystream element: the top byte of a canonical field
    // element is biased, so it is dropped (`circuits/encrypt`).
    for (i, chunk) in pt.chunks_mut(31).enumerate() {
        let ks = keystream(&key, i as u64);
        for (b, k) in chunk.iter_mut().zip(ks[1..].iter()) {
            *b ^= k;
        }
    }
    let value = u64::from_le_bytes(pt[..8].try_into().unwrap());
    let d: [u8; 11] = pt[8..19].try_into().unwrap();
    let r_bytes: [u8; 32] = pt[19..].try_into().unwrap();
    let r = Fr::from_be_bytes_mod_order(&r_bytes);
    if fr_to_bytes(&r) != r_bytes {
        return None;
    }
    let g_d = curve::group_hash(&d)?;
    let pk_d = g_d.mul(ivk);
    let note = Note {
        value,
        d,
        g_d,
        pk_d,
        r,
    };
    (note.commitment() == *cm).then_some(note)
}

/// Decrypts an audit blob (`epk ‖ c...`) with the custodian's secret.
pub fn audit_decrypt(ask: &Fr, blob: &[u8]) -> Option<Vec<Note>> {
    if blob.len() < 64 || !(blob.len() - 64).is_multiple_of(32 * AUDIT_ELEMENTS) {
        return None;
    }
    let epk = Point {
        x: Fr::from_be_bytes_mod_order(&blob[..32]),
        y: Fr::from_be_bytes_mod_order(&blob[32..64]),
    };
    let key = kdf(&epk.mul(ask), &epk);
    let cts: Vec<Fr> = blob[64..]
        .chunks(32)
        .map(Fr::from_be_bytes_mod_order)
        .collect();
    let mut notes = Vec::new();
    for (i, group) in cts.chunks(AUDIT_ELEMENTS).enumerate() {
        let pt: Vec<Fr> = group
            .iter()
            .enumerate()
            .map(|(j, c)| {
                *c - Fr::from_be_bytes_mod_order(&keystream(&key, (AUDIT_ELEMENTS * i + j) as u64))
            })
            .collect();
        // packed = lsb(pk_d.x)·2^152 + value·2^88 + d, as 32 bytes BE:
        // d in [21..32], value in [13..21], the sign in bit 0 of byte 12.
        let packed = pt[0].into_bigint().to_bytes_be();
        if packed[..12].iter().any(|b| *b != 0) || packed[12] & 0xfe != 0 {
            return None;
        }
        let sign = packed[12] & 1;
        let value = u64::from_be_bytes(packed[13..21].try_into().unwrap());
        let d: [u8; 11] = packed[21..32].try_into().unwrap();
        let y = pt[1];
        let mut x = curve::x_from_y(&y)?;
        if (x.into_bigint().to_bytes_be()[31] & 1) != sign {
            x = -x;
        }
        let g_d = curve::group_hash(&d)?;
        notes.push(Note {
            value,
            d,
            g_d,
            pk_d: Point { x, y },
            r: pt[2],
        });
    }
    Some(notes)
}

/// `Poseidon(ENCH, 31-byte chunks)` of the concatenated recipient blobs.
pub fn enc_hash(blobs: &[u8]) -> [u8; 32] {
    let mut inputs = vec![domain_tag("privtx/ench")];
    for chunk in blobs.chunks(31) {
        // A short last chunk sits at the start of its 31 bytes, zero-padded
        // at the end, as `circuits/encrypt.EncHash` and the program do.
        let mut padded = [0u8; 31];
        padded[..chunk.len()].copy_from_slice(chunk);
        inputs.push(Fr::from_be_bytes_mod_order(&padded));
    }
    poseidon(&inputs)
}

/// `Poseidon(AUDIT, apk.x, apk.y, epk.x, epk.y, c..., extra...)`.
pub fn audit_hash(apk: &Point, audit_blob: &[u8], extra: &[[u8; 32]]) -> [u8; 32] {
    let mut inputs = vec![domain_tag("privtx/audit"), apk.x, apk.y];
    inputs.extend(audit_blob.chunks(32).map(Fr::from_be_bytes_mod_order));
    inputs.extend(extra.iter().map(|e| Fr::from_be_bytes_mod_order(e)));
    poseidon(&inputs)
}

/// `Poseidon(TSIGHASH, pool halves, nf_0, nf_1, cm_0, cm_1, audit_hash, enc_hash)`.
pub fn transfer_sighash(
    pool: &[u8; 32],
    nullifiers: &[[u8; 32]; 2],
    commitments: &[[u8; 32]; 2],
    audit_hash: &[u8; 32],
    enc_hash: &[u8; 32],
) -> [u8; 32] {
    let f = |b: &[u8]| Fr::from_be_bytes_mod_order(b);
    poseidon(&[
        domain_tag("privtx/tsighash"),
        f(&pool[..16]),
        f(&pool[16..]),
        f(&nullifiers[0]),
        f(&nullifiers[1]),
        f(&commitments[0]),
        f(&commitments[1]),
        f(audit_hash),
        f(enc_hash),
    ])
}
