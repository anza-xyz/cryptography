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
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/domain"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// NbConstraints is the R1CS size of the circuit as compiled by the pinned gnark
// and Poseidon gadget versions; quoted in README.md.
const NbConstraints = 12587

func randomNote(t *testing.T, value uint64) note.Note {
	t.Helper()
	k, err := note.GenerateSpendingKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fvk := k.FullViewingKey()
	var d note.Diversifier
	if _, err := rand.Read(d[:]); err != nil {
		t.Fatal(err)
	}
	addr, err := fvk.Address(d)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Random(rand.Reader, value, addr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var custodian = encrypt.NewAuditKey(fr.NewElement(31337))

// assign is the witness for n with a fixed ephemeral key and a blob.
func assign(t *testing.T, n *note.Note) *Circuit {
	t.Helper()
	blob, err := encrypt.EncryptNote(rand.Reader, n)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Build(n, &custodian.PK, fr.NewElement(99), blob[:])
	return c
}

func TestMintCircuit(t *testing.T) {
	n := randomNote(t, 1_000_000)
	valid := assign(t, &n)

	wrongCommitment := assign(t, &n)
	cm := n.Commitment()
	cm.Add(&cm, new(fr.Element).SetOne())
	wrongCommitment.Commitment = cm

	// Public value disagrees with the committed one.
	wrongValue := assign(t, &n)
	wrongValue.Value = n.Value + 1

	// value = 2^64 does not fit the range check, whatever the commitment says.
	big64 := new(big.Int).Lsh(big.NewInt(1), ValueBits)
	overflow := assign(t, &n)
	overflow.Value = big64
	overflow.Commitment = commitmentOf(big64, &n)

	// g_d of small order (the identity): the owner relation would bind
	// nothing. The commitment is recomputed so only the order check fails.
	smallOrder := assign(t, &n)
	smallOrder.GD = twistededwards.Point{X: 0, Y: 1}
	smallOrder.Commitment = commitmentWithGD(&n, 0, 1)

	// A valid base that is not GroupHash(d): the custodian could never
	// recompute this note from its audit ciphertext.
	otherBase := assign(t, &n)
	m := n
	m.D = note.DiversifierFromSeed([]byte("other base"))
	other := m.GD()
	otherBase.GD = note.PointVars(&other)
	otherBase.Commitment = m.Commitment()

	// pk_d off the curve.
	offCurve := assign(t, &n)
	offCurve.PKD = twistededwards.Point{X: 1, Y: 1}
	offCurve.Commitment = commitmentWithPKD(&n, 1, 1)

	// The audit ciphertext of another note, or another recipient blob.
	wrongAudit := assign(t, &n)
	wrongAudit.ESK = 100
	wrongBlob := assign(t, &n)
	wrongBlob.EncHash = 1

	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(wrongCommitment),
		test.WithInvalidAssignment(wrongValue),
		test.WithInvalidAssignment(overflow),
		test.WithInvalidAssignment(smallOrder),
		test.WithInvalidAssignment(otherBase),
		test.WithInvalidAssignment(offCurve),
		test.WithInvalidAssignment(wrongAudit),
		test.WithInvalidAssignment(wrongBlob),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

// commitmentOf hashes an out-of-range value the way the circuit would, so the
// only failing constraint is the range check.
func commitmentOf(value *big.Int, n *note.Note) fr.Element {
	var v fr.Element
	v.SetBigInt(value)
	gd := n.GD()
	return poseidon.MustHash(domain.Tag(domain.CM), v, gd.X, gd.Y, n.PKD.X, n.PKD.Y, n.R)
}

// commitmentWithGD hashes the note with another g_d, so only the point
// checks fail.
func commitmentWithGD(n *note.Note, x, y uint64) fr.Element {
	var v, gx, gy fr.Element
	v.SetUint64(n.Value)
	gx.SetUint64(x)
	gy.SetUint64(y)
	return poseidon.MustHash(domain.Tag(domain.CM), v, gx, gy, n.PKD.X, n.PKD.Y, n.R)
}

// commitmentWithPKD hashes the note with another pk_d.
func commitmentWithPKD(n *note.Note, x, y uint64) fr.Element {
	var v, px, py fr.Element
	v.SetUint64(n.Value)
	px.SetUint64(x)
	py.SetUint64(y)
	gd := n.GD()
	return poseidon.MustHash(domain.Tag(domain.CM), v, gd.X, gd.Y, px, py, n.R)
}

func TestZeroValueNoteIsValid(t *testing.T) {
	// Dummy (zero-value) notes must be provable: they pad transactions and
	// inflate the anonymity set.
	n := randomNote(t, 0)
	if err := test.IsSolved(&Circuit{}, assign(t, &n), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	n = randomNote(t, ^uint64(0))
	if err := test.IsSolved(&Circuit{}, assign(t, &n), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("max u64 value rejected: %v", err)
	}
}

// The verifying key must be plain Groth16: no commitment keys, three public inputs.
func TestVerifyingKeyShape(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mint: %d constraints, %d public, %d secret", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	// Pinned so the size quoted in the README moves together with the code;
	// a gnark or Poseidon gadget bump that changes it should update both.
	if got := ccs.GetNbConstraints(); got != NbConstraints {
		t.Fatalf("constraints = %d, want %d (update NbConstraints and README.md)", got, NbConstraints)
	}
	if got := ccs.GetNbPublicVariables(); got != 4 { // "one" wire + commitment + value + audit_hash
		t.Fatalf("public variables = %d, want 4", got)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("circuit declares %d commitments; the on-chain verifier rejects them", n)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	n := randomNote(t, 12345)
	w, err := frontend.NewWitness(assign(t, &n), ecc.BN254.ScalarField())
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
	// Public witness order is commitment, value, audit_hash.
	vec, ok := pub.Vector().(fr.Vector)
	if !ok || len(vec) != 3 {
		t.Fatalf("public witness vector = %v", pub.Vector())
	}
	if cm := n.Commitment(); !vec[0].Equal(&cm) {
		t.Fatal("public input 0 is not the commitment")
	}
	if !vec[1].IsUint64() || vec[1].Uint64() != n.Value {
		t.Fatal("public input 1 is not the value")
	}
}
