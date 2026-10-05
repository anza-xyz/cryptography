// Package smoke is a trivial circuit that exercises the whole pipeline:
// gnark compile → Groth16 setup → prove → export → groth16-convert → verifier
// program. It carries no protocol logic; the real circuits live beside it.
package smoke

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit proves A·B = C with all three values public, the same statement as
// the verifier repository's own gnark fixture.
type Circuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
	C frontend.Variable `gnark:",public"`
}

// Define constrains C = A·B.
func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	return nil
}

// Assignment builds the witness for a·b = c.
func Assignment(a, b uint64) *Circuit {
	return &Circuit{A: a, B: b, C: a * b}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
