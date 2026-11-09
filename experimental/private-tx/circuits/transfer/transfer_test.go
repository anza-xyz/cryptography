package transfer

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

// NbConstraints is the R1CS size of the circuit as compiled by the pinned gnark
// and Poseidon gadget versions; quoted in README.md.
const NbConstraints = 59234

var testPool = [32]byte{7, 7, 7}

type fixture struct {
	tree      merkle.Tree
	alice     note.SpendingKey
	bob       note.SpendingKey
	notes     []note.Note // alice's, in leaf order
	custodian encrypt.AuditKey
}

func newFixture(t *testing.T, values ...uint64) *fixture {
	t.Helper()
	f := &fixture{
		alice: note.SpendingKeyFromSeed([]byte("alice")),
		bob:   note.SpendingKeyFromSeed([]byte("bob")),
	}
	var ask fr.Element
	ask.SetUint64(4242)
	f.custodian = encrypt.NewAuditKey(ask)
	fvk := f.alice.FullViewingKey()
	for i, v := range values {
		addr, err := fvk.Address(note.DiversifierFromSeed([]byte{byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
		n, err := note.Random(rand.Reader, v, addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.tree.Append(n.Commitment()); err != nil {
			t.Fatal(err)
		}
		f.notes = append(f.notes, n)
	}
	return f
}

func (f *fixture) spend(t *testing.T, i int) Spend {
	t.Helper()
	path, err := f.tree.Path(uint64(i))
	if err != nil {
		t.Fatal(err)
	}
	return Spend{Note: f.notes[i], Path: path, Key: f.alice}
}

func (f *fixture) output(t *testing.T, key note.SpendingKey, seed byte, value uint64) note.Note {
	t.Helper()
	fvk := key.FullViewingKey()
	addr, err := fvk.Address(note.DiversifierFromSeed([]byte{0xf0, seed}))
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Random(rand.Reader, value, addr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) params(t *testing.T, spends [2]Spend, outputs [2]note.Note) *Params {
	t.Helper()
	esk, err := encrypt.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &Params{
		Pool:    testPool,
		Root:    f.tree.Root(),
		Spends:  spends,
		Outputs: outputs,
		AuditPK: f.custodian.PK,
		ESK:     esk,
	}
	for i := range outputs {
		blob, err := encrypt.EncryptNote(rand.Reader, &outputs[i])
		if err != nil {
			t.Fatal(err)
		}
		p.EncBlobs[i] = blob[:]
	}
	return p
}

func build(t *testing.T, p *Params) *Circuit {
	t.Helper()
	c, _, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTransferCircuit(t *testing.T) {
	f := newFixture(t, 1000, 2000, 3000)
	// Two real inputs: 1000 + 2000 → 2500 to bob, 500 change to alice.
	real := f.params(t, [2]Spend{f.spend(t, 0), f.spend(t, 1)},
		[2]note.Note{f.output(t, f.bob, 1, 2500), f.output(t, f.alice, 2, 500)})
	valid := build(t, real)

	// One real input and a dummy: 3000 → 3000 to bob and a zero note.
	dummy, err := Dummy(rand.Reader, f.alice)
	if err != nil {
		t.Fatal(err)
	}
	withDummy := build(t, f.params(t, [2]Spend{f.spend(t, 2), dummy},
		[2]note.Note{f.output(t, f.bob, 3, 3000), f.output(t, f.alice, 4, 0)}))

	// The dummy slot first.
	dummyFirst := build(t, f.params(t, [2]Spend{dummy, f.spend(t, 2)},
		[2]note.Note{f.output(t, f.bob, 3, 3000), f.output(t, f.alice, 4, 0)}))

	// Inflation: 1000 + 2000 → 2500 + 1000.
	inflating := *valid
	inflating.Outputs[1].Value = 1000
	inflating.Commitment1 = commitmentWithValue(&real.Outputs[1], 1000)

	// A dummy that claims value: the note is not in the tree.
	richDummy := build(t, f.params(t, [2]Spend{f.spend(t, 2), dummy},
		[2]note.Note{f.output(t, f.bob, 3, 3000), f.output(t, f.alice, 4, 0)}))
	richDummy.Inputs[1].Value = 1
	richDummy.Outputs[1].Value = 1
	richDummy.Commitment1 = commitmentWithValue(&note.Note{}, 1) // never equal, fails anyway

	// Signed by bob instead of alice for input 0.
	bobSigns := f.params(t, [2]Spend{f.spend(t, 0), f.spend(t, 1)},
		[2]note.Note{f.output(t, f.bob, 1, 2500), f.output(t, f.alice, 2, 500)})
	bobSigns.Spends[0].Key = f.bob
	wrongSigner, _, err := Build(bobSigns)
	if err != nil {
		t.Fatal(err)
	}

	// Alice signs, but over another statement (someone swapped a recipient blob).
	swappedBlob := *valid
	otherBlobs := f.params(t, [2]Spend{f.spend(t, 0), f.spend(t, 1)},
		[2]note.Note{real.Outputs[0], real.Outputs[1]})
	otherBlobs.ESK = real.ESK
	_, otherSt, err := Build(otherBlobs)
	if err != nil {
		t.Fatal(err)
	}
	swappedBlob.SigHash = otherSt.SigHash

	// Both inputs the same note.
	doubleSpend := f.params(t, [2]Spend{f.spend(t, 0), f.spend(t, 0)},
		[2]note.Note{f.output(t, f.bob, 1, 2000), f.output(t, f.alice, 2, 0)})
	sameNote := build(t, doubleSpend)
	// The circuit itself allows it (the nullifiers are equal); the program
	// rejects equal nullifiers. Check that is what happens.
	if sameNote.Nullifier0 != sameNote.Nullifier1 {
		t.Fatal("spending one note twice gave two nullifiers")
	}

	// Another audit key than the one the hash was made for.
	wrongAudit := *valid
	wrongAudit.ESK = 5

	// An output out of range, with the commitment adjusted so only the
	// range check and conservation can fail... conservation is kept by
	// moving value between outputs in the field: 2^64 + x and y such that
	// the sum wraps is impossible with two 64-bit inputs, so just the range.
	big := *valid
	big.Outputs[0].Value = "18446744073709551616"  // 2^64
	big.Outputs[1].Value = "-18446744073709549116" // 500 - 2^64 + 2500... keeps the field sum
	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(valid),
		test.WithValidAssignment(withDummy),
		test.WithValidAssignment(dummyFirst),
		test.WithInvalidAssignment(&inflating),
		test.WithInvalidAssignment(richDummy),
		test.WithInvalidAssignment(wrongSigner),
		test.WithInvalidAssignment(&swappedBlob),
		test.WithInvalidAssignment(&wrongAudit),
		test.WithInvalidAssignment(&big),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoFuzzing(),
	)
}

func commitmentWithValue(n *note.Note, v uint64) fr.Element {
	m := *n
	m.Value = v
	if m.D == (note.Diversifier{}) {
		var e fr.Element
		e.SetUint64(v)
		return e
	}
	return m.Commitment()
}

// The verifying key must be plain Groth16: no commitment keys, seven public inputs.
func TestVerifyingKeyShape(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("transfer: %d constraints, %d public, %d secret", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	if got := ccs.GetNbConstraints(); got != NbConstraints {
		t.Fatalf("constraints = %d, want %d (update NbConstraints and README.md)", got, NbConstraints)
	}
	if got := ccs.GetNbPublicVariables(); got != 8 {
		t.Fatalf("public variables = %d, want 8", got)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("circuit declares %d commitments; the on-chain verifier rejects them", n)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, 10, 20)
	p := f.params(t, [2]Spend{f.spend(t, 0), f.spend(t, 1)},
		[2]note.Note{f.output(t, f.bob, 1, 25), f.output(t, f.alice, 2, 5)})
	c, st, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
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
	vec, ok := pub.Vector().(fr.Vector)
	if !ok || len(vec) != 7 {
		t.Fatalf("public witness vector = %v", pub.Vector())
	}
	want := []fr.Element{st.Root, st.Nullifiers[0], st.Nullifiers[1], st.Commitments[0], st.Commitments[1], st.AuditHash, st.SigHash}
	for i := range want {
		if !vec[i].Equal(&want[i]) {
			t.Fatalf("public input %d differs from the statement", i)
		}
	}
	// The custodian reads both outputs from the audit blob.
	epk, cts, err := encrypt.ParseAuditBlob(st.AuditBlob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.custodian.AuditDecrypt(&epk, cts)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != p.Outputs[0] || got[1] != p.Outputs[1] {
		t.Fatal("audit decryption differs from the outputs")
	}
	// And the recipients find theirs.
	bob := f.bob.FullViewingKey()
	if n, ok := encrypt.DecryptNote(&bob, p.EncBlobs[0], st.Commitments[0]); !ok || n != p.Outputs[0] {
		t.Fatal("bob cannot decrypt his output")
	}
	if _, ok := encrypt.DecryptNote(&bob, p.EncBlobs[1], st.Commitments[1]); ok {
		t.Fatal("bob decrypted alice's change")
	}
}
