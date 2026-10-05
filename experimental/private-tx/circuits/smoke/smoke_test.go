package smoke

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestSmokeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(Assignment(3, 5)),
		test.WithInvalidAssignment(&Circuit{A: 3, B: 5, C: 16}),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

// The verifying key must be plain Groth16: no commitment keys, since the
// on-chain verifier rejects gnark's commitment extension.
func TestNoCommitments(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("circuit declares %d commitments", n)
	}
}
