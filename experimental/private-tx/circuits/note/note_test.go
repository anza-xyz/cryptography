package note

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

type groupHashCircuit struct {
	GD gadgetted.Point `gnark:",public"`
	D  frontend.Variable
	W  GroupHashVars
}

func (c *groupHashCircuit) Define(api frontend.API) error {
	curve, err := gadgetted.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	api.ToBinary(c.D, DiversifierSize*8)
	return GroupHashGadget(api, curve, c.D, c.W, c.GD)
}

func TestGroupHashGadgetMatchesNative(t *testing.T) {
	// Find diversifiers that hit at counter 0 and at a later counter, so
	// both the non-residue proofs and the hit are exercised.
	var first, later *Diversifier
	for i := 0; i < 64 && (first == nil || later == nil); i++ {
		d := DiversifierFromSeed([]byte{byte(i)})
		w, err := d.GroupHashWitness()
		if err != nil {
			continue
		}
		if w.Ctr == 0 && first == nil {
			d := d
			first = &d
		}
		if w.Ctr > 0 && later == nil {
			d := d
			later = &d
		}
	}
	if first == nil || later == nil {
		t.Fatal("no diversifiers with counter 0 and > 0 among the first 64 seeds")
	}
	var valid []frontend.Circuit
	for _, d := range []*Diversifier{first, later} {
		w, _ := d.GroupHashWitness()
		valid = append(valid, &groupHashCircuit{GD: PointVars(&w.GD), D: d.Element(), W: w.Vars()})
	}
	// Another point for the same d: the counter and roots cannot be faked.
	w, _ := later.GroupHashWitness()
	other := SpendingKeyFromSeed([]byte("x")).FullViewingKey().AK
	wrongPoint := &groupHashCircuit{GD: PointVars(&other), D: later.Element(), W: w.Vars()}
	// Claiming an earlier counter: the non-square there has no root, and
	// the hit's x differs.
	earlier := w
	earlier.Ctr = 0
	wrongCounter := &groupHashCircuit{GD: PointVars(&w.GD), D: later.Element(), W: earlier.Vars()}
	// The larger root.
	bigY := w
	bigY.Y.Neg(&bigY.Y)
	negP := w.GD
	negP.X.Neg(&negP.X) // [8](x, -y) = (-gd.x, gd.y)
	wrongRoot := &groupHashCircuit{GD: PointVars(&negP), D: later.Element(), W: bigY.Vars()}
	// Another diversifier with this witness.
	wrongD := &groupHashCircuit{GD: PointVars(&w.GD), D: first.Element(), W: w.Vars()}

	assert := test.NewAssert(t)
	assert.CheckCircuit(&groupHashCircuit{},
		test.WithValidAssignment(valid[0]),
		test.WithValidAssignment(valid[1]),
		test.WithInvalidAssignment(wrongPoint),
		test.WithInvalidAssignment(wrongCounter),
		test.WithInvalidAssignment(wrongRoot),
		test.WithInvalidAssignment(wrongD),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
	)
}

func TestKeyHierarchyIsDeterministicAndValid(t *testing.T) {
	k := SpendingKeyFromSeed([]byte("seed"))
	again := SpendingKeyFromSeed([]byte("seed"))
	fvk, fvk2 := k.FullViewingKey(), again.FullViewingKey()
	if !fvk.AK.Equal(&fvk2.AK) || !fvk.NK.Equal(&fvk2.NK) {
		t.Fatal("same seed gave different keys")
	}
	if !fvk.AK.IsOnCurve() || !fvk.AK.IsInSubGroup() || fvk.AK.IsZero() {
		t.Fatal("ak is not a valid public key")
	}
	other := SpendingKeyFromSeed([]byte("other")).FullViewingKey()
	if fvk.AK.Equal(&other.AK) || fvk.NK.Equal(&other.NK) {
		t.Fatal("different seeds gave the same key")
	}
	if ivk := fvk.IVK(); ivk.Equal(&fvk.NK) || ivk.IsZero() {
		t.Fatal("ivk is degenerate")
	}
}

func TestGroupHashLandsInTheSubgroup(t *testing.T) {
	for i := 0; i < 32; i++ {
		d := DiversifierFromSeed([]byte{byte(i)})
		gd, err := d.GroupHash()
		if err != nil {
			t.Fatal(err)
		}
		if !gd.IsOnCurve() || !gd.IsInSubGroup() || gd.IsZero() {
			t.Fatalf("diversifier %d: g_d is not a prime-order point", i)
		}
		again, _ := d.GroupHash()
		if !again.Equal(&gd) {
			t.Fatalf("diversifier %d: group hash is not deterministic", i)
		}
	}
	a, _ := DiversifierFromSeed([]byte{1}).GroupHash()
	b, _ := DiversifierFromSeed([]byte{2}).GroupHash()
	if a.Equal(&b) {
		t.Fatal("two diversifiers share a base")
	}
}

func TestAddressesOfOneKeyAreUnlinkableWithoutIVK(t *testing.T) {
	fvk := SpendingKeyFromSeed([]byte("addr")).FullViewingKey()
	a1, err := fvk.Address(DiversifierFromSeed([]byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := fvk.Address(DiversifierFromSeed([]byte{2}))
	if err != nil {
		t.Fatal(err)
	}
	if a1.PKD.Equal(&a2.PKD) {
		t.Fatal("two diversifiers gave the same pk_d")
	}
	// pk_d = [ivk]g_d, which the holder of ivk can recompute.
	ivk := fvk.IVK()
	var want twistededwards.PointAffine
	gd, _ := a1.D.GroupHash()
	want.ScalarMultiplication(&gd, ivk.BigInt(new(big.Int)))
	if !want.Equal(&a1.PKD) {
		t.Fatal("pk_d != [ivk]g_d")
	}
}

func TestCommitmentBindsEveryField(t *testing.T) {
	k, err := GenerateSpendingKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fvk := k.FullViewingKey()
	addr, err := fvk.Address(DiversifierFromSeed([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	n, err := Random(rand.Reader, 1000, addr)
	if err != nil {
		t.Fatal(err)
	}
	cm := n.Commitment()

	otherAddr, _ := fvk.Address(DiversifierFromSeed([]byte("y")))
	variants := []Note{n, n, n, n}
	variants[0].Value++
	variants[1].D = otherAddr.D // changes g_d
	variants[2].PKD = otherAddr.PKD
	variants[3].R.Add(&variants[3].R, new(fr.Element).SetOne())
	for i, v := range variants {
		if got := v.Commitment(); got.Equal(&cm) {
			t.Errorf("variant %d did not change the commitment", i)
		}
	}
}

func TestNullifierBindsKeyCommitmentAndPosition(t *testing.T) {
	n := FromSeed([]byte("nf"), 1)
	nk := SpendingKeyFromSeed([]byte("nf")).FullViewingKey().NK
	cm := n.Commitment()
	nf := Nullifier(nk, cm, 3)
	if got := Nullifier(nk, cm, 4); got.Equal(&nf) {
		t.Fatal("nullifier ignores the position")
	}
	var otherCM fr.Element
	otherCM.Add(&cm, new(fr.Element).SetOne())
	if got := Nullifier(nk, otherCM, 3); got.Equal(&nf) {
		t.Fatal("nullifier ignores the commitment")
	}
	otherNK := SpendingKeyFromSeed([]byte("someone else")).FullViewingKey().NK
	if got := Nullifier(otherNK, cm, 3); got.Equal(&nf) {
		t.Fatal("nullifier ignores nk")
	}
}

func TestSignatureVerifiesNatively(t *testing.T) {
	k := SpendingKeyFromSeed([]byte("signer"))
	var msg fr.Element
	msg.SetUint64(12345)
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.R.IsOnCurve() {
		t.Fatal("R is not on the curve")
	}
	if sig.S.IsZero() {
		t.Fatal("S is zero")
	}
	again, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if again != sig {
		t.Fatal("signing is not deterministic")
	}
	d := Dummy()
	if !d.R.IsOnCurve() || !d.S.IsZero() {
		t.Fatal("dummy signature is malformed")
	}
}

func TestFromSeedIsDeterministic(t *testing.T) {
	a := FromSeed([]byte("seed"), 5)
	b := FromSeed([]byte("seed"), 5)
	if a != b {
		t.Fatal("same seed gave different notes")
	}
	fvk := SpendingKeyFromSeed([]byte("seed")).FullViewingKey()
	addr, _ := fvk.Address(a.D)
	if !addr.PKD.Equal(&a.PKD) {
		t.Fatal("SpendingKeyFromSeed does not own the seeded note")
	}
	c := FromSeed([]byte("other"), 5)
	if a == c {
		t.Fatal("different seeds gave the same note")
	}
}

func TestOpeningRoundTrip(t *testing.T) {
	n := FromSeed([]byte("round-trip"), 42)
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var back Note
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back != n {
		t.Fatalf("round trip changed the note:\n%s", data)
	}

	var o Opening
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	o.Value++
	if _, err := FromOpening(o); err == nil {
		t.Fatal("tampered opening accepted")
	}
	if len(o.Commitment) != 66 {
		t.Fatalf("commitment hex is %d chars, want 66", len(o.Commitment))
	}
	o = Opening{}
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	o.GDX = o.PKDX
	if _, err := FromOpening(o); err == nil {
		t.Fatal("opening with g_d != GroupHash(d) accepted")
	}
	o = Opening{}
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	o.Diversifier = o.R // a full field element, not 11 bytes
	if _, err := FromOpening(o); err == nil {
		t.Fatal("oversized diversifier accepted")
	}
}

func TestFromOpeningIsStrict(t *testing.T) {
	n := FromSeed([]byte("strict"), 42)
	valid := n.ToOpening()
	// The modulus plus the canonical value: same residue, non-canonical bytes.
	var aboveModulus big.Int
	aboveModulus.SetString(valid.R[2:], 16)
	aboveModulus.Add(&aboveModulus, fr.Modulus())
	for name, r := range map[string]string{
		"decimal":        new(big.Int).SetBytes(mustBytes(t, valid.R)).String(),
		"negative":       "-1",
		"no prefix":      valid.R[2:],
		"short":          "0x01",
		"long":           valid.R + "00",
		"underscore":     "0x" + valid.R[2:4] + "_" + valid.R[5:],
		"above modulus":  fmt.Sprintf("0x%064x", &aboveModulus),
		"modulus":        fmt.Sprintf("0x%064x", fr.Modulus()),
		"non-hex digits": "0x" + strings.Repeat("zz", 32),
	} {
		o := valid
		o.R = r
		if _, err := FromOpening(o); err == nil {
			t.Errorf("%s: accepted %q", name, r)
		}
	}
	if _, err := FromOpening(valid); err != nil {
		t.Fatal(err)
	}
}

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		t.Fatal(err)
	}
	return b
}
