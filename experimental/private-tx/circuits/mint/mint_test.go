package mint

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

func randomNote(t *testing.T, value uint64) note.Note {
	t.Helper()
	var sk fr.Element
	if _, err := sk.SetRandom(); err != nil {
		t.Fatal(err)
	}
	n, err := note.Random(rand.Reader, value, note.DeriveOwnerPK(sk))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMintCircuit(t *testing.T) {
	n := randomNote(t, 1_000_000)
	valid := Assignment(&n)

	wrongCommitment := Assignment(&n)
	var cm fr.Element
	cm.SetInterface(valid.Commitment)
	cm.Add(&cm, new(fr.Element).SetOne())
	wrongCommitment.Commitment = cm

	// Public value disagrees with the committed one.
	wrongValue := Assignment(&n)
	wrongValue.Value = n.Value + 1

	// value = 2^64 does not fit the range check, whatever the commitment says.
	big64 := new(big.Int).Lsh(big.NewInt(1), ValueBits)
	overflow := Assignment(&n)
	overflow.Value = big64
	overflow.Commitment = commitmentOf(big64, &n)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(wrongCommitment),
		test.WithInvalidAssignment(wrongValue),
		test.WithInvalidAssignment(overflow),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

// commitmentOf hashes an out-of-range value the way the circuit would, so the
// only failing constraint is the range check.
func commitmentOf(value *big.Int, n *note.Note) fr.Element {
	var v fr.Element
	v.SetBigInt(value)
	return mustHash(v, n.OwnerPK, n.Rho, n.R)
}

func TestZeroValueNoteIsValid(t *testing.T) {
	// Dummy (zero-value) notes must be provable: anonymity-set inflation
	// relies on them (goals.md).
	n := randomNote(t, 0)
	if err := test.IsSolved(&Circuit{}, Assignment(&n), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	n = randomNote(t, ^uint64(0))
	if err := test.IsSolved(&Circuit{}, Assignment(&n), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("max u64 value rejected: %v", err)
	}
}

// The verifying key must be plain Groth16: no commitment keys, one public input.
func TestVerifyingKeyShape(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mint: %d constraints, %d public, %d secret", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	if got := ccs.GetNbPublicVariables(); got != 3 { // "one" wire + commitment + value
		t.Fatalf("public variables = %d, want 3", got)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("circuit declares %d commitments; the on-chain verifier rejects them", n)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	n := randomNote(t, 12345)
	w, err := frontend.NewWitness(Assignment(&n), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
}
