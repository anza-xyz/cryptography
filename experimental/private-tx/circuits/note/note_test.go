package note

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestCommitmentBindsEveryField(t *testing.T) {
	var pk fr.Element
	pk.SetUint64(7)
	n, err := Random(rand.Reader, 1000, pk)
	if err != nil {
		t.Fatal(err)
	}
	cm := n.Commitment()

	variants := []Note{n, n, n, n}
	variants[0].Value++
	variants[1].OwnerPK.SetUint64(8)
	variants[2].Rho.Add(&variants[2].Rho, new(fr.Element).SetOne())
	variants[3].R.Add(&variants[3].R, new(fr.Element).SetOne())
	for i, v := range variants {
		if got := v.Commitment(); got.Equal(&cm) {
			t.Errorf("variant %d did not change the commitment", i)
		}
	}
}

func TestNullifierBindsOwnerAndRho(t *testing.T) {
	n := FromSeed([]byte("nf"), 1)
	nf := n.Nullifier()
	other := n
	other.Value++
	other.R.Add(&other.R, new(fr.Element).SetOne())
	if got := other.Nullifier(); !got.Equal(&nf) {
		t.Fatal("nullifier depends on value or r")
	}
	other = n
	other.Rho.Add(&other.Rho, new(fr.Element).SetOne())
	if got := other.Nullifier(); got.Equal(&nf) {
		t.Fatal("nullifier ignores rho")
	}
	other = n
	other.OwnerPK.Add(&other.OwnerPK, new(fr.Element).SetOne())
	if got := other.Nullifier(); got.Equal(&nf) {
		t.Fatal("nullifier ignores owner_pk")
	}
}

func TestFromSeedIsDeterministic(t *testing.T) {
	a := FromSeed([]byte("seed"), 5)
	b := FromSeed([]byte("seed"), 5)
	if a != b {
		t.Fatal("same seed gave different notes")
	}
	if pk := DeriveOwnerPK(SpendingKeyFromSeed([]byte("seed"))); !pk.Equal(&a.OwnerPK) {
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
}

func TestFromOpeningIsStrict(t *testing.T) {
	n := FromSeed([]byte("strict"), 42)
	valid := n.ToOpening()
	// The modulus plus the canonical value: same residue, non-canonical bytes.
	var aboveModulus big.Int
	aboveModulus.SetString(valid.Rho[2:], 16)
	aboveModulus.Add(&aboveModulus, fr.Modulus())
	for name, rho := range map[string]string{
		"decimal":        new(big.Int).SetBytes(mustBytes(t, valid.Rho)).String(),
		"negative":       "-1",
		"no prefix":      valid.Rho[2:],
		"short":          "0x01",
		"long":           valid.Rho + "00",
		"underscore":     "0x" + valid.Rho[2:4] + "_" + valid.Rho[5:],
		"above modulus":  fmt.Sprintf("0x%064x", &aboveModulus),
		"modulus":        fmt.Sprintf("0x%064x", fr.Modulus()),
		"non-hex digits": "0x" + strings.Repeat("zz", 32),
	} {
		o := valid
		o.Rho = rho
		if _, err := FromOpening(o); err == nil {
			t.Errorf("%s: accepted %q", name, rho)
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
