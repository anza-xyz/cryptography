// Package client is the wallet side of the protocol: what a user's software
// does between the chain and the circuits.
//
//   - Ledger is the pool's history as an indexer reconstructs it from the
//     Mint and Transfer instructions: the leaves in order, each leaf's
//     recipient blob, and the nullifiers published. From it the wallet
//     rebuilds the commitment tree and any leaf's Merkle path.
//   - Wallet holds a spending key, scans a Ledger by trial-decrypting every
//     blob with its incoming viewing key, and builds the witness and
//     statement of a shield, a transfer or an unshield.
//   - Prover turns a witness into a Groth16 proof with a (development)
//     setup; the fixture CLI writes its output in the verifier's formats.
//
// Nothing here talks to a cluster: the Rust e2e crate plays the indexer
// (it parses the instructions it submits) and the transaction builder.
package client

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/mint"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/transfer"
)

// Ledger is a pool's history: leaves with their recipient blobs, and the
// nullifiers seen.
type Ledger struct {
	Leaves     []fr.Element
	Blobs      [][]byte
	Nullifiers map[fr.Element]bool

	tree *merkle.Tree // rebuilt lazily, dropped on Append
}

// Append records a new leaf and its recipient blob.
func (l *Ledger) Append(cm fr.Element, blob []byte) {
	l.Leaves = append(l.Leaves, cm)
	l.Blobs = append(l.Blobs, append([]byte(nil), blob...))
	l.tree = nil
}

// Spend records a published nullifier.
func (l *Ledger) Spend(nf fr.Element) {
	if l.Nullifiers == nil {
		l.Nullifiers = map[fr.Element]bool{}
	}
	l.Nullifiers[nf] = true
}

// Tree is the commitment tree, rebuilt once per ledger state.
func (l *Ledger) Tree() *merkle.Tree {
	if l.tree == nil {
		var tr merkle.Tree
		for _, cm := range l.Leaves {
			if _, err := tr.Append(cm); err != nil {
				panic(err)
			}
		}
		l.tree = &tr
	}
	return l.tree
}

// Root is the current root.
func (l *Ledger) Root() fr.Element { return l.Tree().Root() }

// Path is the Merkle path of leaf index.
func (l *Ledger) Path(index uint64) (merkle.Path, error) { return l.Tree().Path(index) }

// Wallet is a spending key and what it can do.
type Wallet struct {
	Key note.SpendingKey
}

// FullViewingKey returns the wallet's (ak, nk).
func (w *Wallet) FullViewingKey() note.FullViewingKey { return w.Key.FullViewingKey() }

// Address returns the wallet's address for diversifier d.
func (w *Wallet) Address(d note.Diversifier) (note.Address, error) {
	fvk := w.FullViewingKey()
	return fvk.Address(d)
}

// Owned is a note the wallet can spend, with its position in the tree.
type Owned struct {
	Note  note.Note
	Index uint64
}

// Nullifier is the nullifier the wallet would publish for the note.
func (w *Wallet) Nullifier(o Owned) fr.Element {
	return note.Nullifier(w.FullViewingKey().NK, o.Note.Commitment(), o.Index)
}

// Scan trial-decrypts every blob in the ledger and returns the wallet's
// unspent notes in leaf order.
func (w *Wallet) Scan(l *Ledger) []Owned {
	fvk := w.FullViewingKey()
	var owned []Owned
	for i, blob := range l.Blobs {
		n, ok := encrypt.DecryptNote(&fvk, blob, l.Leaves[i])
		if !ok {
			continue
		}
		o := Owned{Note: n, Index: uint64(i)}
		if l.Nullifiers[w.Nullifier(o)] {
			continue
		}
		owned = append(owned, o)
	}
	return owned
}

// Shield is a mint of value to addr: the note, its witness, statement and
// recipient blob.
type Shield struct {
	Note      note.Note
	Circuit   *mint.Circuit
	Statement *mint.Statement
	EncBlob   []byte
}

// NewShield builds a shield of value to addr under the pool's audit key.
func NewShield(rng io.Reader, addr note.Address, value uint64, apk *twistededwards.PointAffine) (*Shield, error) {
	n, err := note.Random(rng, value, addr)
	if err != nil {
		return nil, err
	}
	blob, err := encrypt.EncryptNote(rng, &n)
	if err != nil {
		return nil, err
	}
	esk, err := encrypt.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	c, st := mint.Build(&n, apk, esk, blob[:])
	return &Shield{Note: n, Circuit: c, Statement: st, EncBlob: blob[:]}, nil
}

// Payment is one transfer output.
type Payment struct {
	To    note.Address
	Value uint64
}

// Transfer is a built transfer: witness, statement, the output notes and
// their recipient blobs.
type Transfer struct {
	Circuit   *transfer.Circuit
	Statement *transfer.Statement
	Outputs   [transfer.NumOutputs]note.Note
	EncBlobs  [transfer.NumOutputs][]byte
}

// Pay spends up to two of the wallet's notes for two payments, which must
// use up the inputs exactly (a change payment to one of the wallet's own
// addresses is just another payment). Missing inputs are dummies.
func (w *Wallet) Pay(rng io.Reader, l *Ledger, pool [32]byte, apk *twistededwards.PointAffine, spends []Owned, payments [transfer.NumOutputs]Payment) (*Transfer, error) {
	if len(spends) == 0 || len(spends) > transfer.NumInputs {
		return nil, fmt.Errorf("client: %d inputs, want 1..%d", len(spends), transfer.NumInputs)
	}
	if len(spends) == 2 && spends[0].Index == spends[1].Index {
		return nil, fmt.Errorf("client: leaf %d spent twice", spends[0].Index)
	}
	p := &transfer.Params{Pool: pool, Root: l.Root(), AuditPK: *apk}
	for i := range p.Spends {
		if i < len(spends) {
			path, err := l.Path(spends[i].Index)
			if err != nil {
				return nil, err
			}
			p.Spends[i] = transfer.Spend{Note: spends[i].Note, Path: path, Key: w.Key}
			continue
		}
		d, err := transfer.Dummy(rng, w.Key)
		if err != nil {
			return nil, err
		}
		p.Spends[i] = d
	}
	t := &Transfer{}
	for i, pay := range payments {
		n, err := note.Random(rng, pay.Value, pay.To)
		if err != nil {
			return nil, err
		}
		blob, err := encrypt.EncryptNote(rng, &n)
		if err != nil {
			return nil, err
		}
		p.Outputs[i] = n
		p.EncBlobs[i] = blob[:]
		t.Outputs[i] = n
		t.EncBlobs[i] = blob[:]
	}
	esk, err := encrypt.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	p.ESK = esk
	c, st, err := transfer.Build(p)
	if err != nil {
		return nil, err
	}
	t.Circuit, t.Statement = c, st
	return t, nil
}

// Unshield builds the owner's burn of o to destination.
func (w *Wallet) Unshield(l *Ledger, pool, destination [32]byte, o Owned) (*burn.Circuit, error) {
	path, err := l.Path(o.Index)
	if err != nil {
		return nil, err
	}
	return burn.Unshield(&o.Note, &path, w.Key, pool, destination)
}

// Forfeit builds the custodian's burn of a note it decrypted from the
// audit ciphertext, with the owner's registered full viewing key.
func Forfeit(l *Ledger, pool, destination [32]byte, n note.Note, index uint64, fvk note.FullViewingKey) (*burn.Circuit, error) {
	path, err := l.Path(index)
	if err != nil {
		return nil, err
	}
	return burn.Forfeit(&n, &path, fvk, pool, destination), nil
}

// Prover holds a compiled circuit and a development Groth16 key pair, so
// one setup can serve several proofs. A real deployment needs an MPC
// ceremony.
type Prover struct {
	Name string
	CCS  constraint.ConstraintSystem
	PK   groth16.ProvingKey
	VK   groth16.VerifyingKey
}

// NewProver compiles and sets up a circuit.
func NewProver(name string, compile func() (constraint.ConstraintSystem, error)) (*Prover, error) {
	ccs, err := compile()
	if err != nil {
		return nil, fmt.Errorf("%s: compile: %w", name, err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("%s: setup: %w", name, err)
	}
	return &Prover{Name: name, CCS: ccs, PK: pk, VK: vk}, nil
}

// Prove proves an assignment and self-verifies, returning the proof and
// the public witness.
func (p *Prover) Prove(assignment frontend.Circuit) (groth16.Proof, witness.Witness, error) {
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: witness: %w", p.Name, err)
	}
	public, err := full.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: public witness: %w", p.Name, err)
	}
	proof, err := groth16.Prove(p.CCS, p.PK, full)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: prove: %w", p.Name, err)
	}
	if err := groth16.Verify(proof, p.VK, public); err != nil {
		return nil, nil, fmt.Errorf("%s: self-verify: %w", p.Name, err)
	}
	return proof, public, nil
}
