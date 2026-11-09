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
const NbConstraints = 20919

var (
	testPool        = [32]byte{1, 2, 3}
	testDestination = [32]byte{4, 5, 6}
)

// pool builds a tree of n seeded notes and returns it with the notes and
// their spending keys.
func pool(t *testing.T, n int) (*merkle.Tree, []note.Note, []note.SpendingKey) {
	t.Helper()
	var tr merkle.Tree
	notes := make([]note.Note, n)
	keys := make([]note.SpendingKey, n)
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

func unshield(t *testing.T, n *note.Note, path *merkle.Path, k note.SpendingKey) *Circuit {
	t.Helper()
	c, err := Unshield(n, path, k, testPool, testDestination)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func forfeit(n *note.Note, path *merkle.Path, k note.SpendingKey) *Circuit {
	return Forfeit(n, path, k.FullViewingKey(), testPool, testDestination)
}

func TestBurnCircuit(t *testing.T) {
	tr, notes, keys := pool(t, 4)
	target := 2
	path, err := tr.Path(uint64(target))
	if err != nil {
		t.Fatal(err)
	}
	n, sk := notes[target], keys[target]
	valid := unshield(t, &n, &path, sk)
	forced := forfeit(&n, &path, sk)
	if root, got := tr.Root(), path.Root(n.Commitment()); !got.Equal(&root) {
		t.Fatal("assignment root != tree root")
	}

	// Signed by another note's owner, whose keys do not own this note.
	wrongKey := unshield(t, &n, &path, keys[0])

	// The owner's signature over another destination: a replay with the
	// recipient swapped.
	otherDestination := unshield(t, &n, &path, sk)
	otherDestination.SigHash = SigHash(testPool, [32]byte{9}, note.Nullifier(sk.FullViewingKey().NK, n.Commitment(), path.Index), n.Value)

	// The owner's signature over the same destination in another pool.
	otherPool := unshield(t, &n, &path, sk)
	otherPool.SigHash = SigHash([32]byte{9}, testDestination, note.Nullifier(sk.FullViewingKey().NK, n.Commitment(), path.Index), n.Value)

	// Unshield with the forfeiture's dummy signature.
	noSignature := forfeit(&n, &path, sk)
	noSignature.Forced = 0

	// Forfeiture with someone else's full viewing key: the nullifier would
	// not be the note's.
	wrongFVK := forfeit(&n, &path, keys[0])

	// Forfeiture with the right ak but a made-up nk, publishing a
	// nullifier of the custodian's choosing.
	wrongNK := forfeit(&n, &path, sk)
	var fakeNK fr.Element
	fakeNK.SetUint64(42)
	wrongNK.NK = fakeNK
	wrongNK.Nullifier = note.Nullifier(fakeNK, n.Commitment(), path.Index)

	// Forced with a bogus flag value.
	notBoolean := forfeit(&n, &path, sk)
	notBoolean.Forced = 2

	// A note that is not in the tree.
	outsider := note.FromSeed([]byte("not in the pool"), 100)
	notInTree := Forfeit(&outsider, &path, note.SpendingKeyFromSeed([]byte("not in the pool")).FullViewingKey(), testPool, testDestination)
	notInTree.Root = tr.Root()

	// The right note with a stale (different) root.
	wrongRoot := forfeit(&n, &path, sk)
	wrongRoot.Root = merkle.EmptyRoot()

	// Public value disagrees with the committed one.
	wrongValue := unshield(t, &n, &path, sk)
	wrongValue.Value = n.Value + 1

	// Nullifier of another position.
	wrongNullifier := forfeit(&n, &path, sk)
	wrongNullifier.Nullifier = note.Nullifier(sk.FullViewingKey().NK, n.Commitment(), path.Index+1)

	// Path of another leaf.
	otherPath, err := tr.Path(1)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := unshield(t, &n, &otherPath, sk)
	wrongPath.Root = tr.Root()

	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(valid),
		test.WithValidAssignment(forced),
		test.WithInvalidAssignment(wrongKey),
		test.WithInvalidAssignment(otherDestination),
		test.WithInvalidAssignment(otherPool),
		test.WithInvalidAssignment(noSignature),
		test.WithInvalidAssignment(wrongFVK),
		test.WithInvalidAssignment(wrongNK),
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
		if err := test.IsSolved(&Circuit{}, unshield(t, &notes[i], &path, keys[i]), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("unshield leaf %d: %v", i, err)
		}
		if err := test.IsSolved(&Circuit{}, forfeit(&notes[i], &path, keys[i]), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("forfeit leaf %d: %v", i, err)
		}
	}
}

func TestSigHashBindsEveryField(t *testing.T) {
	var nf fr.Element
	nf.SetUint64(77)
	base := SigHash(testPool, testDestination, nf, 7)
	var otherNF fr.Element
	otherNF.SetUint64(78)
	variants := []fr.Element{
		SigHash([32]byte{1, 2, 4}, testDestination, nf, 7),
		SigHash([32]byte{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, testDestination, nf, 7),
		SigHash(testPool, [32]byte{4, 5, 7}, nf, 7),
		SigHash(testPool, [32]byte{4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, nf, 7),
		SigHash(testPool, testDestination, otherNF, 7),
		SigHash(testPool, testDestination, nf, 8),
	}
	for i, v := range variants {
		if v.Equal(&base) {
			t.Errorf("variant %d did not change the sighash", i)
		}
	}
}

// The verifying key must be plain Groth16: no commitment keys, five public inputs.
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
	if got := ccs.GetNbPublicVariables(); got != 6 { // "one" wire + root + nullifier + value + forced + sighash
		t.Fatalf("public variables = %d, want 6", got)
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
	nf := note.Nullifier(keys[1].FullViewingKey().NK, notes[1].Commitment(), 1)
	for _, c := range []*Circuit{unshield(t, &notes[1], &path, keys[1]), forfeit(&notes[1], &path, keys[1])} {
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
		// Public witness order is root, nullifier, value, forced, sighash.
		vec, ok := pub.Vector().(fr.Vector)
		if !ok || len(vec) != 5 {
			t.Fatalf("public witness vector = %v", pub.Vector())
		}
		if root := tr.Root(); !vec[0].Equal(&root) {
			t.Fatal("public input 0 is not the root")
		}
		if !vec[1].Equal(&nf) {
			t.Fatal("public input 1 is not the nullifier")
		}
		if !vec[2].IsUint64() || vec[2].Uint64() != notes[1].Value {
			t.Fatal("public input 2 is not the value")
		}
		if !vec[3].IsUint64() || vec[3].Uint64() != uint64(c.Forced.(int)) {
			t.Fatalf("public input 3 is not forced = %v", c.Forced)
		}
		if sh := SigHash(testPool, testDestination, nf, notes[1].Value); !vec[4].Equal(&sh) {
			t.Fatal("public input 4 is not the sighash")
		}
	}
}
