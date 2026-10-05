package note

import (
	"crypto/rand"
	"encoding/json"
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

func TestFromSeedIsDeterministic(t *testing.T) {
	a := FromSeed([]byte("seed"), 5)
	b := FromSeed([]byte("seed"), 5)
	if a != b {
		t.Fatal("same seed gave different notes")
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
