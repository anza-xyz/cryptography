// Package domain separates every Poseidon use in the protocol: each hash
// takes a distinct constant as its first input, so a digest from one use can
// never be mistaken for a digest from another, whatever the widths happen to
// be. The tags are short ASCII names read as big-endian integers, which keeps
// them below the field modulus and lets the on-chain program (Rust) spell the
// same constants without a table.
package domain

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// Names of every domain. Keep this list in sync with the pool program's
// `state.rs` and the e2e crate.
const (
	// Commitment: Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r).
	CM = "privtx/cm"
	// Nullifier: Poseidon(NF, nk, cm, leaf index).
	NF = "privtx/nf"
	// Nullifier key: Poseidon(NK, sk).
	NK = "privtx/nk"
	// Spend authorizing key seed: Poseidon(ASK, sk).
	ASK = "privtx/ask"
	// Incoming viewing key: Poseidon(IVK, ak.x, ak.y, nk).
	IVK = "privtx/ivk"
	// Diversifier group hash: x = Poseidon(GD, d, counter).
	GD = "privtx/gd"
	// Commitment tree node: Poseidon(NODE, left, right).
	NODE = "privtx/node"
	// Burn sighash: Poseidon(SIGHASH, pool halves, destination halves, nullifier, value).
	SIGHASH = "privtx/sighash"
	// Transfer sighash: Poseidon(TSIGHASH, pool halves, nf_1, nf_2, cm_1, cm_2, audit_hash, enc_hash).
	TSIGHASH = "privtx/tsighash"
	// Note encryption key: Poseidon(KDF, ss.x, ss.y, epk.x, epk.y).
	KDF = "privtx/kdf"
	// Note encryption keystream: Poseidon(ENC, key, counter).
	ENC = "privtx/enc"
	// Audit statement: Poseidon(AUDIT, apk, epk, ciphertext elements..., extra...).
	AUDIT = "privtx/audit"
	// Recipient ciphertext binding: Poseidon(ENCH, 31-byte chunks of the blobs).
	ENCH = "privtx/ench"
)

// Tag is the field element of a domain name: its ASCII bytes as a big-endian
// integer.
func Tag(name string) fr.Element {
	if len(name) >= fr.Bytes {
		panic("domain: name too long for one field element")
	}
	var e fr.Element
	e.SetBytes([]byte(name))
	return e
}
