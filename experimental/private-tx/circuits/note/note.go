// Package note defines the shielded-pool note and its Poseidon commitment.
//
// A note is (value, owner_pk, rho, r). Its commitment is
//
//	cm = Poseidon(value, owner_pk, rho, r)
//
// with the circom-compatible Poseidon of package poseidon (width 5). Each pool
// holds a single asset, so a note carries no asset field.
//
//   - value:    the amount, an unsigned 64-bit integer.
//   - owner_pk: the recipient's public key, an opaque field element here; the
//     key hierarchy is fixed by the protocol spec (Epic 1). DeriveOwnerPK
//     gives the provisional derivation used by the fixtures.
//   - rho:      per-note uniqueness; the nullifier input.
//   - r:        commitment randomness, hides the other fields.
//
// Spending or forfeiting a note publishes its nullifier
//
//	nf = Poseidon(owner_pk, rho)
//
// Sapling's PRF_nk(rho) with the public key in place of the secret nullifier
// key: anyone holding the opening can derive it. That is what lets the
// custodian, who learns openings through the audit ciphertexts, forfeit a
// note without the owner's key (C_burn, forced); the price is that the note's
// creator can also recognize the nullifier when the note is spent. The
// derivation is provisional (key hierarchy, Epic 1) and lives only here, so
// every circuit that emits a nullifier changes together.
package note

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"

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

// Nullifier returns Poseidon(owner_pk, rho).
func (n *Note) Nullifier() fr.Element {
	return poseidon.MustHash(n.OwnerPK, n.Rho)
}

// CommitmentGadget constrains and returns Poseidon(value, owner_pk, rho, r).
func CommitmentGadget(api frontend.API, value, ownerPK, rho, r frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, value, ownerPK, rho, r)
}

// NullifierGadget constrains and returns Poseidon(owner_pk, rho).
func NullifierGadget(api frontend.API, ownerPK, rho frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, ownerPK, rho)
}

// DeriveOwnerPK is the provisional owner key derivation pk = Poseidon(sk).
func DeriveOwnerPK(sk fr.Element) fr.Element {
	return poseidon.MustHash(sk)
}

// OwnerPKGadget constrains and returns Poseidon(sk), the owner key of sk.
func OwnerPKGadget(api frontend.API, sk frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, sk)
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
// fixtures: each field is SHA-256(seed ‖ label) reduced into the field, and
// the owner is SpendingKeyFromSeed(seed).
func FromSeed(seed []byte, value uint64) Note {
	return Note{
		Value:   value,
		OwnerPK: DeriveOwnerPK(SpendingKeyFromSeed(seed)),
		Rho:     deriveFromSeed(seed, "rho"),
		R:       deriveFromSeed(seed, "r"),
	}
}

// SpendingKeyFromSeed is the spending key of the notes FromSeed derives from
// seed.
func SpendingKeyFromSeed(seed []byte) fr.Element {
	return deriveFromSeed(seed, "spending-key")
}

func deriveFromSeed(seed []byte, label string) fr.Element {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(label))
	var e fr.Element
	e.SetBytes(h.Sum(nil))
	return e
}

// Opening is the JSON form of a note together with its commitment; field
// elements are 0x-prefixed big-endian hex, exactly 32 bytes, canonical
// (below the field modulus). That is the only form FromOpening accepts.
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
		OwnerPK:    Hex32(&n.OwnerPK),
		Rho:        Hex32(&n.Rho),
		R:          Hex32(&n.R),
		Commitment: Hex32(&cm),
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
		if err := ParseHex32(f.src, f.dst); err != nil {
			return Note{}, fmt.Errorf("note: %s: %w", f.name, err)
		}
	}
	var cm fr.Element
	if err := ParseHex32(o.Commitment, &cm); err != nil {
		return Note{}, fmt.Errorf("note: commitment: %w", err)
	}
	if got := n.Commitment(); !got.Equal(&cm) {
		return Note{}, fmt.Errorf("note: commitment mismatch: got %s", Hex32(&got))
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

// Hex32 encodes e as 0x-prefixed big-endian hex, 32 bytes (66 characters).
func Hex32(e *fr.Element) string {
	b := e.Bytes() // big-endian, 32 bytes
	return "0x" + hex.EncodeToString(b[:])
}

// ParseHex32 is the strict inverse of Hex32: it rejects anything but a
// 0x-prefixed 64-digit hex string holding a canonical field element, so a
// value another parser (e.g. the Rust e2e crate) would refuse cannot slip
// through reduced.
func ParseHex32(s string, out *fr.Element) error {
	if len(s) != 2+2*fr.Bytes || s[:2] != "0x" {
		return fmt.Errorf("want 0x-prefixed %d-byte hex, got %q", fr.Bytes, s)
	}
	var b [fr.Bytes]byte
	if _, err := hex.Decode(b[:], []byte(s[2:])); err != nil {
		return err
	}
	if err := out.SetBytesCanonical(b[:]); err != nil {
		return fmt.Errorf("%w: %q", err, s)
	}
	return nil
}
