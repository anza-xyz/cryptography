// Package note defines the shielded-pool note and its Poseidon commitment.
//
// A note is (value, owner_pk, rho, r). Its commitment is
//
//	cm = Poseidon(value, owner_pk, rho, r)
//
// with the circom-compatible Poseidon of package poseidon (width 5). The pool
// fixes the asset, so there is no asset field (high_level_design.md §2.1).
//
//   - value:    the amount, an unsigned 64-bit integer.
//   - owner_pk: the recipient's public key, an opaque field element here; the
//     key hierarchy is fixed by the protocol spec (Epic 1). DeriveOwnerPK
//     gives the provisional derivation used by the fixtures.
//   - rho:      per-note uniqueness; later the nullifier input.
//   - r:        commitment randomness, hides the other fields.
package note

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Note is an opened note.
type Note struct {
	Value   uint64
	OwnerPK fr.Element
	Rho     fr.Element
	R       fr.Element
}

// Commitment returns Poseidon(value, owner_pk, rho, r).
func (n *Note) Commitment() fr.Element {
	var v fr.Element
	v.SetUint64(n.Value)
	return poseidon.MustHash(v, n.OwnerPK, n.Rho, n.R)
}

// DeriveOwnerPK is the provisional owner key derivation pk = Poseidon(sk).
func DeriveOwnerPK(sk fr.Element) fr.Element {
	return poseidon.MustHash(sk)
}

// Random returns a note of the given value for owner_pk with fresh rho and r.
func Random(rng io.Reader, value uint64, ownerPK fr.Element) (Note, error) {
	n := Note{Value: value, OwnerPK: ownerPK}
	if err := randomElement(rng, &n.Rho); err != nil {
		return Note{}, err
	}
	if err := randomElement(rng, &n.R); err != nil {
		return Note{}, err
	}
	return n, nil
}

func randomElement(rng io.Reader, out *fr.Element) error {
	var buf [64]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return err
	}
	out.SetBytes(buf[:]) // reduces mod r; 512 bits of entropy keeps it uniform
	return nil
}

// FromSeed derives a note deterministically from a seed, for reproducible
// fixtures: each field is SHA-256(seed ‖ label) reduced into the field.
func FromSeed(seed []byte, value uint64) Note {
	derive := func(label string) fr.Element {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte(label))
		var e fr.Element
		e.SetBytes(h.Sum(nil))
		return e
	}
	sk := derive("spending-key")
	return Note{
		Value:   value,
		OwnerPK: DeriveOwnerPK(sk),
		Rho:     derive("rho"),
		R:       derive("r"),
	}
}

// Opening is the JSON form of a note together with its commitment; field
// elements are 0x-prefixed big-endian hex, 32 bytes.
type Opening struct {
	Value      uint64 `json:"value"`
	OwnerPK    string `json:"owner_pk"`
	Rho        string `json:"rho"`
	R          string `json:"r"`
	Commitment string `json:"commitment"`
}

// ToOpening serializes the note and its commitment.
func (n *Note) ToOpening() Opening {
	cm := n.Commitment()
	return Opening{
		Value:      n.Value,
		OwnerPK:    hex32(&n.OwnerPK),
		Rho:        hex32(&n.Rho),
		R:          hex32(&n.R),
		Commitment: hex32(&cm),
	}
}

// FromOpening parses an Opening and checks its commitment.
func FromOpening(o Opening) (Note, error) {
	n := Note{Value: o.Value}
	for _, f := range []struct {
		name string
		src  string
		dst  *fr.Element
	}{
		{"owner_pk", o.OwnerPK, &n.OwnerPK},
		{"rho", o.Rho, &n.Rho},
		{"r", o.R, &n.R},
	} {
		if _, err := f.dst.SetString(f.src); err != nil {
			return Note{}, fmt.Errorf("note: %s: %w", f.name, err)
		}
	}
	var cm fr.Element
	if _, err := cm.SetString(o.Commitment); err != nil {
		return Note{}, fmt.Errorf("note: commitment: %w", err)
	}
	if got := n.Commitment(); !got.Equal(&cm) {
		return Note{}, fmt.Errorf("note: commitment mismatch: got %s", hex32(&got))
	}
	return n, nil
}

// MarshalJSON writes the Opening form.
func (n Note) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.ToOpening())
}

// UnmarshalJSON reads the Opening form and checks the commitment.
func (n *Note) UnmarshalJSON(data []byte) error {
	var o Opening
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	parsed, err := FromOpening(o)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

func hex32(e *fr.Element) string {
	b := e.Bytes() // big-endian, 32 bytes
	return fmt.Sprintf("0x%064x", new(big.Int).SetBytes(b[:]))
}
