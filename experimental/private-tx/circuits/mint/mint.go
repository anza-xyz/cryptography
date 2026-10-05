// Package mint is C_mint: issuance of one note into a pool with a public
// amount.
//
// The issuing institution creates a note for a recipient and publishes the
// amount and the note commitment. The proof shows the commitment opens to a
// well-formed note carrying exactly that amount, so the pool program can
// account for the minted value (and, for a wrapped asset, match it against
// the vault deposit; high_level_design.md §2.2) while the recipient stays
// hidden. Who may mint is enforced by the pool program (issuer authority), not
// in-circuit.
//
// Public inputs, in order:
//
//	0  commitment   Poseidon(value, owner_pk, rho, r)
//	1  value        the note amount, < 2^64
//
// Private witness: owner_pk, rho, r.
package mint

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// ValueBits is the width of the note value range check.
const ValueBits = 64

// Circuit is the mint relation. Field order fixes the public input order.
type Circuit struct {
	Commitment frontend.Variable `gnark:",public"`
	Value      frontend.Variable `gnark:",public"`

	OwnerPK frontend.Variable
	Rho     frontend.Variable
	R       frontend.Variable
}

// Define constrains value ∈ [0, 2^64) and commitment = Poseidon(value, owner_pk, rho, r).
//
// The value is public, so the on-chain verifier already rejects a non-canonical
// scalar; the bit decomposition still bounds it to 64 bits so every leaf in the
// tree carries a value later conservation checks can add without wrapping. It
// is a plain ToBinary rather than gnark's std/rangecheck: the latter uses a
// commitment-based lookup under Groth16, which adds a commitment key to the
// verifying key and a Pedersen commitment to the proof, and the on-chain
// verifier implements plain Groth16 only.
func (c *Circuit) Define(api frontend.API) error {
	api.ToBinary(c.Value, ValueBits)
	cm, err := poseidon.HashGadget(api, c.Value, c.OwnerPK, c.Rho, c.R)
	if err != nil {
		return err
	}
	api.AssertIsEqual(cm, c.Commitment)
	return nil
}

// Assignment builds the full witness for a note.
func Assignment(n *note.Note) *Circuit {
	return &Circuit{
		Commitment: n.Commitment(),
		Value:      n.Value,
		OwnerPK:    n.OwnerPK,
		Rho:        n.Rho,
		R:          n.R,
	}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
