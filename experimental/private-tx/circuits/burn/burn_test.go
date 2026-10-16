package burn

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

// NbConstraints is the R1CS size of the circuit as compiled by the pinned gnark
// and Poseidon gadget versions; quoted in README.md.
const NbConstraints = 8532

// pool builds a tree of n seeded notes and returns it with the notes and
// their spending keys.
func pool(t *testing.T, n int) (*merkle.Tree, []note.Note, []fr.Element) {
	t.Helper()
	var tr merkle.Tree
	notes := make([]note.Note, n)
	keys := make([]fr.Element, n)
	for i := range notes {
		seed := []byte{byte(i)}
		notes[i] = note.FromSeed(seed, uint64(100*(i+1)))
		keys[i] = note.SpendingKeyFromSeed(seed)
		if _, err := tr.Append(notes[i].Commitment()); err != nil {
			t.Fatal(err)
		}
	}
	return &tr, notes, keys
}

func TestBurnCircuit(t *testing.T) {
	tr, notes, keys := pool(t, 4)
	target := 2
	path, err := tr.Path(uint64(target))
	if err != nil {
		t.Fatal(err)
	}
	n, sk := notes[target], keys[target]
	unshield := Unshield(&n, &path, sk)
	forfeit := Forfeit(&n, &path)
	if root, got := tr.Root(), path.Root(n.Commitment()); !got.Equal(&root) {
		t.Fatal("assignment root != tree root")
	}

	// Unshield with another note's key: no consent.
	wrongKey := Unshield(&n, &path, keys[0])

	// Forced with a bogus flag value.
	notBoolean := Forfeit(&n, &path)
	notBoolean.Forced = 2

	// A note that is not in the tree.
	outsider := note.FromSeed([]byte("not in the pool"), 100)
	notInTree := Forfeit(&outsider, &path)
	notInTree.Root = tr.Root()

	// The right note with a stale (different) root.
	wrongRoot := Forfeit(&n, &path)
	wrongRoot.Root = merkle.EmptyRoot()

	// Public value disagrees with the committed one.
	wrongValue := Unshield(&n, &path, sk)
	wrongValue.Value = n.Value + 1

	// Nullifier of another note.
	wrongNullifier := Forfeit(&n, &path)
	wrongNullifier.Nullifier = notes[0].Nullifier()

	// Path of another leaf.
	otherPath, err := tr.Path(1)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := Unshield(&n, &otherPath, sk)
	wrongPath.Root = tr.Root()

	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(unshield),
		test.WithValidAssignment(forfeit),
		test.WithInvalidAssignment(wrongKey),
		test.WithInvalidAssignment(notBoolean),
		test.WithInvalidAssignment(notInTree),
		test.WithInvalidAssignment(wrongRoot),
		test.WithInvalidAssignment(wrongValue),
		test.WithInvalidAssignment(wrongNullifier),
		test.WithInvalidAssignment(wrongPath),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoFuzzing(),
	)
}

func TestEveryLeafIsBurnable(t *testing.T) {
	// Including the last one, whose siblings are all empty subtrees.
	tr, notes, keys := pool(t, 3)
	for i := range notes {
		path, err := tr.Path(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(&Circuit{}, Unshield(&notes[i], &path, keys[i]), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("unshield leaf %d: %v", i, err)
		}
		if err := test.IsSolved(&Circuit{}, Forfeit(&notes[i], &path), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("forfeit leaf %d: %v", i, err)
		}
	}
}

// The verifying key must be plain Groth16: no commitment keys, four public inputs.
func TestVerifyingKeyShape(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("burn: %d constraints, %d public, %d secret", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	// Pinned so the size quoted in the README moves together with the code.
	if got := ccs.GetNbConstraints(); got != NbConstraints {
		t.Fatalf("constraints = %d, want %d (update NbConstraints and README.md)", got, NbConstraints)
	}
	if got := ccs.GetNbPublicVariables(); got != 5 { // "one" wire + root + nullifier + value + forced
		t.Fatalf("public variables = %d, want 5", got)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("circuit declares %d commitments; the on-chain verifier rejects them", n)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	tr, notes, keys := pool(t, 2)
	path, err := tr.Path(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Circuit{Unshield(&notes[1], &path, keys[1]), Forfeit(&notes[1], &path)} {
		w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
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
		// Public witness order is root, nullifier, value, forced.
		vec, ok := pub.Vector().(fr.Vector)
		if !ok || len(vec) != 4 {
			t.Fatalf("public witness vector = %v", pub.Vector())
		}
		if root := tr.Root(); !vec[0].Equal(&root) {
			t.Fatal("public input 0 is not the root")
		}
		if nf := notes[1].Nullifier(); !vec[1].Equal(&nf) {
			t.Fatal("public input 1 is not the nullifier")
		}
		if !vec[2].IsUint64() || vec[2].Uint64() != notes[1].Value {
			t.Fatal("public input 2 is not the value")
		}
		if !vec[3].IsUint64() || vec[3].Uint64() != uint64(c.Forced.(int)) {
			t.Fatalf("public input 3 is not forced = %v", c.Forced)
		}
	}
}
