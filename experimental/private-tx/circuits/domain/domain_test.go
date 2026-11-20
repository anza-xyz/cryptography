package domain

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestTagsAreDistinctAndSmall(t *testing.T) {
	names := []string{CM, NF, NK, ASK, IVK, GD, NODE, SIGHASH, TSIGHASH, KDF, ENC, AUDIT, ENCH}
	seen := map[fr.Element]string{}
	for _, n := range names {
		tag := Tag(n)
		if other, dup := seen[tag]; dup {
			t.Fatalf("%q and %q share a tag", n, other)
		}
		seen[tag] = n
		// The tag is the plain big-endian integer of the name, so the Rust
		// side can derive it from the same string.
		var want fr.Element
		want.SetBytes([]byte(n))
		if !tag.Equal(&want) {
			t.Fatalf("%q: tag is not the big-endian integer of its name", n)
		}
	}
	if got := Tag("privtx/cm"); got.IsZero() {
		t.Fatal("zero tag")
	}
}
