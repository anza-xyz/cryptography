// Package burn is C_burn: removal of one note from the pool with a public
// amount, either by its owner (unshield) or by the custodian (forfeiture).
//
// Both are the same relation: the note is in the commitment tree, its
// nullifier is published so it cannot be spent again, and its amount is
// published so the pool program can release the backing (vault withdrawal,
// supply decrease). They differ only in who authorizes:
//
//   - forced = 0, unshield: the prover knows the owner's spending key. The
//     proof itself carries the owner's consent, so the program accepts it from
//     anyone.
//   - forced = 1, forfeiture: no ownership check. The custodian, who learns
//     the opening from the audit ciphertext, removes the note without the
//     owner's key. The program must require the custodian's signature when
//     this flag is set; the circuit only tells it which case it is in.
//
// Public inputs, in order:
//
//	0  root        a commitment tree root the program accepts
//	1  nullifier   Poseidon(owner_pk, rho), see package note
//	2  value       the note amount
//	3  forced      0 or 1
//
// Private witness: owner_pk, rho, r, spending key (ignored when forced),
// leaf index, Merkle siblings.
//
// The value needs no range check here: it is bound to a leaf of the tree,
// and every leaf was range-checked by the circuit that created it. Where the
// released amount goes is the program's business; the spec should bind the
// destination into the statement so a proof cannot be replayed from the
// mempool with another recipient.
package burn

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

// Circuit is the burn relation. Field order fixes the public input order.
type Circuit struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Value     frontend.Variable `gnark:",public"`
	Forced    frontend.Variable `gnark:",public"`

	OwnerPK     frontend.Variable
	Rho         frontend.Variable
	R           frontend.Variable
	SpendingKey frontend.Variable
	Path        merkle.PathVars
}

// Define constrains forced ∈ {0, 1}, forced ∨ owner_pk = Poseidon(sk),
// root = MerkleRoot(Poseidon(value, owner_pk, rho, r), path) and
// nullifier = Poseidon(owner_pk, rho).
func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Forced)
	pk, err := note.OwnerPKGadget(api, c.SpendingKey)
	if err != nil {
		return err
	}
	// (1 - forced) · (pk - owner_pk) = 0: ownership unless forced.
	api.AssertIsEqual(api.Mul(api.Sub(1, c.Forced), api.Sub(pk, c.OwnerPK)), 0)

	cm, err := note.CommitmentGadget(api, c.Value, c.OwnerPK, c.Rho, c.R)
	if err != nil {
		return err
	}
	root, err := merkle.RootGadget(api, cm, c.Path)
	if err != nil {
		return err
	}
	api.AssertIsEqual(root, c.Root)

	nf, err := note.NullifierGadget(api, c.OwnerPK, c.Rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(nf, c.Nullifier)
	return nil
}

// Unshield builds the owner's witness for burning n, which sits in the tree
// at path, with spending key sk.
func Unshield(n *note.Note, path *merkle.Path, sk fr.Element) *Circuit {
	c := assignment(n, path)
	c.Forced = 0
	c.SpendingKey = sk
	return c
}

// Forfeit builds the custodian's witness for burning n without the owner's
// key.
func Forfeit(n *note.Note, path *merkle.Path) *Circuit {
	c := assignment(n, path)
	c.Forced = 1
	c.SpendingKey = 0
	return c
}

func assignment(n *note.Note, path *merkle.Path) *Circuit {
	return &Circuit{
		Root:      path.Root(n.Commitment()),
		Nullifier: n.Nullifier(),
		Value:     n.Value,
		OwnerPK:   n.OwnerPK,
		Rho:       n.Rho,
		R:         n.R,
		Path:      path.Vars(),
	}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
