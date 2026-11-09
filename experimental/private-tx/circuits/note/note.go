// Package note defines the shielded-pool note, its Poseidon commitment and
// nullifier, and the key hierarchy behind them. The structure is Sapling's,
// with Poseidon for every hash and PRF and gnark-crypto's twisted Edwards
// curve over BN254 Fr (Baby Jubjub in a = -1 form) as the embedded group.
//
// # Keys
//
//	sk                               spending key, a field element
//	ask = KeyGen(Poseidon(ASK, sk))  spend authorizing key, EdDSA secret
//	ak  = [ask]G                     spend authorizing public key
//	nk  = Poseidon(NK, sk)           nullifier key
//	fvk = (ak, nk)                   full viewing key
//	ivk = Poseidon(IVK, ak.x, ak.y, nk)   incoming viewing key, used as a scalar
//	g_d = GroupHash(d)               diversifier base, d an 11-byte diversifier (replayed in-circuit)
//	pk_d = [ivk]g_d                  diversified transmission key
//	address = (d, pk_d)
//
// Spending a note needs ask (to sign) and nk (to derive the nullifier);
// seeing and forfeiting a note needs fvk only. Institutions register their
// clients' fvk, which is what lets the custodian audit and forfeit.
//
// # Note
//
//	note = (value, d, pk_d, r)
//	cm   = Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r)
//	nf   = Poseidon(NF, nk, cm, leaf index)
//
// The nullifier takes the note's position, as Sapling's does (rho = cm +
// [position]J there): two notes with the same opening are different leaves
// and get different nullifiers, so a sender cannot hand out notes that
// collide ("Faerie Gold"). Only the holder of nk can derive a nullifier,
// so a note's creator cannot tell when it is spent.
//
// Every Poseidon call is domain-separated by its first input; see package
// domain. The EdDSA challenge hash is MiMC (gnark's native pairing of signer
// and gadget), which never needs to match anything on-chain since the
// signature only ever meets the circuit.
package note

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/cmp"
	gadgeteddsa "github.com/consensys/gnark/std/signature/eddsa"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/domain"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// DiversifierSize is the diversifier length in bytes, as in Sapling.
const DiversifierSize = 11

// Diversifier selects one of a key's addresses.
type Diversifier [DiversifierSize]byte

// Element is the diversifier as a field element (big-endian).
func (d Diversifier) Element() fr.Element {
	var e fr.Element
	e.SetBytes(d[:])
	return e
}

// GroupHashTries bounds the try-and-increment of GroupHash, so the gadget
// can replay it. A diversifier whose first curve point needs more tries is
// unusable (probability 2^-8): pick another.
const GroupHashTries = 8

// NonResidue is a fixed quadratic non-residue of Fr (5), the witness of
// "not a square": r is not a square iff NonResidue·r is.
var NonResidue = fr.NewElement(5)

// groupHashRHS is y² as a function of x on the curve:
// a x² + y² = 1 + D x² y²  =>  y² = (1 - a x²) / (1 - D x²).
func groupHashRHS(x fr.Element) (fr.Element, bool) {
	params := twistededwards.GetEdwardsCurve()
	one := fr.NewElement(1)
	var xx, num, den, rhs fr.Element
	xx.Square(&x)
	num.Mul(&params.A, &xx)
	num.Sub(&one, &num)
	den.Mul(&params.D, &xx)
	den.Sub(&one, &den)
	if den.IsZero() {
		return fr.Element{}, false
	}
	rhs.Div(&num, &den)
	return rhs, true
}

// GroupHash maps the diversifier to g_d, a point of the prime-order
// subgroup: x = Poseidon(GD, d, counter) for counter = 0, 1, ..., the first
// x that is the abscissa of a curve point, with the smaller y, cleared of
// the cofactor. Fails if no counter below GroupHashTries gives a point.
func (d Diversifier) GroupHash() (twistededwards.PointAffine, error) {
	w, err := d.GroupHashWitness()
	if err != nil {
		return twistededwards.PointAffine{}, err
	}
	return w.GD, nil
}

// GroupHashWitness is GroupHash with everything the gadget replays: the
// counter that hit, the point before cofactor clearing, and for every
// counter before it a square root of NonResidue·rhs, which is what shows
// that rhs was not a square.
type GroupHashWitness struct {
	Ctr   uint64
	X, Y  fr.Element
	Roots [GroupHashTries]fr.Element
	GD    twistededwards.PointAffine
}

// GroupHashWitness runs the group hash and records the witness.
func (d Diversifier) GroupHashWitness() (GroupHashWitness, error) {
	params := twistededwards.GetEdwardsCurve()
	var w GroupHashWitness
	var ctr fr.Element
	for i := uint64(0); i < GroupHashTries; i++ {
		ctr.SetUint64(i)
		x := poseidon.MustHash(domain.Tag(domain.GD), d.Element(), ctr)
		rhs, ok := groupHashRHS(x)
		if !ok {
			return w, fmt.Errorf("note: diversifier %x hits a pole at counter %d", d[:], i)
		}
		var y fr.Element
		if y.Sqrt(&rhs) == nil {
			// Not a square: NonResidue·rhs is.
			var nr fr.Element
			nr.Mul(&NonResidue, &rhs)
			if w.Roots[i].Sqrt(&nr) == nil {
				panic("note: neither rhs nor NonResidue·rhs is a square")
			}
			continue
		}
		var negY fr.Element
		negY.Neg(&y)
		if negY.Cmp(&y) < 0 {
			y = negY
		}
		p := twistededwards.PointAffine{X: x, Y: y}
		p.ScalarMultiplication(&p, params.Cofactor.BigInt(new(big.Int)))
		if p.IsZero() {
			return w, fmt.Errorf("note: diversifier %x gives a small-order point at counter %d", d[:], i)
		}
		w.Ctr, w.X, w.Y, w.GD = i, x, y, p
		return w, nil
	}
	return w, fmt.Errorf("note: no group hash for diversifier %x in %d tries", d[:], GroupHashTries)
}

// GroupHashVars is GroupHashWitness as circuit variables.
type GroupHashVars struct {
	Ctr   frontend.Variable
	X, Y  frontend.Variable
	Roots [GroupHashTries]frontend.Variable
}

// Vars converts the witness.
func (w *GroupHashWitness) Vars() GroupHashVars {
	v := GroupHashVars{Ctr: w.Ctr, X: w.X, Y: w.Y}
	for i := range w.Roots {
		v.Roots[i] = w.Roots[i]
	}
	return v
}

// GroupHashGadget constrains gd = GroupHash(d), replaying the
// try-and-increment: for counters before the witness's, rhs is shown to be
// a non-square by a root of NonResidue·rhs; at the witness's counter,
// (x, y) is on the curve with y the smaller root; the counter is below
// GroupHashTries; gd = [8](x, y). The caller range-checks d.
func GroupHashGadget(api frontend.API, curve gadgetted.Curve, d frontend.Variable, w GroupHashVars, gd gadgetted.Point) error {
	params := twistededwards.GetEdwardsCurve()
	// lt_i = [i < ctr], eq_i = [i == ctr]; exactly one eq_i is 1.
	var lt frontend.Variable = 1
	var hits frontend.Variable = 0
	for i := 0; i < GroupHashTries; i++ {
		eq := api.IsZero(api.Sub(w.Ctr, i))
		lt = api.Sub(lt, eq)
		hits = api.Add(hits, eq)
		x, err := poseidon.HashGadget(api, domain.Tag(domain.GD), d, i)
		if err != nil {
			return err
		}
		xx := api.Mul(x, x)
		num := api.Sub(1, api.Mul(params.A, xx))
		den := api.Sub(1, api.Mul(params.D, xx))
		rhs := api.Div(num, den)
		// i < ctr: root_i² = NonResidue · rhs_i.
		api.AssertIsEqual(api.Mul(lt, api.Sub(api.Mul(w.Roots[i], w.Roots[i]), api.Mul(NonResidue, rhs))), 0)
		// i == ctr: x = x_i and y² = rhs_i.
		api.AssertIsEqual(api.Mul(eq, api.Sub(w.X, x)), 0)
		api.AssertIsEqual(api.Mul(eq, api.Sub(api.Mul(w.Y, w.Y), rhs)), 0)
	}
	api.AssertIsEqual(hits, 1)
	// y is the smaller root: y ≤ (r - 1) / 2.
	half := new(big.Int).Rsh(fr.Modulus(), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, w.Y, half), 1)
	p := gadgetted.Point{X: w.X, Y: w.Y}
	curve.AssertIsOnCurve(p)
	q := curve.Double(curve.Double(curve.Double(p)))
	api.AssertIsEqual(q.X, gd.X)
	api.AssertIsEqual(q.Y, gd.Y)
	return nil
}

// SpendingKey is sk with the keys derived from it.
type SpendingKey struct {
	sk  fr.Element
	ask *eddsa.PrivateKey
	nk  fr.Element
}

// NewSpendingKey derives every key from sk.
func NewSpendingKey(sk fr.Element) SpendingKey {
	askSeed := poseidon.MustHash(domain.Tag(domain.ASK), sk)
	seed := askSeed.Bytes()
	ask, err := eddsa.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		panic(err) // the reader always has the 32 bytes the generator reads
	}
	return SpendingKey{
		sk:  sk,
		ask: ask,
		nk:  poseidon.MustHash(domain.Tag(domain.NK), sk),
	}
}

// GenerateSpendingKey draws sk from rng.
func GenerateSpendingKey(rng io.Reader) (SpendingKey, error) {
	var sk fr.Element
	if err := randomElement(rng, &sk); err != nil {
		return SpendingKey{}, err
	}
	return NewSpendingKey(sk), nil
}

// SpendingKeyFromSeed is a deterministic key for fixtures and tests:
// sk = SHA-256(seed ‖ "sk") reduced into the field.
func SpendingKeyFromSeed(seed []byte) SpendingKey {
	return NewSpendingKey(deriveFromSeed(seed, "sk"))
}

// FullViewingKey returns (ak, nk).
func (k SpendingKey) FullViewingKey() FullViewingKey {
	return FullViewingKey{AK: k.ask.PublicKey.A, NK: k.nk}
}

// Sign signs msg (a field element) with ask, MiMC as the challenge hash.
func (k SpendingKey) Sign(msg fr.Element) (Signature, error) {
	m := msg.Bytes()
	raw, err := k.ask.Sign(m[:], hash.MIMC_BN254.New())
	if err != nil {
		return Signature{}, err
	}
	var sig eddsa.Signature
	if _, err := sig.SetBytes(raw); err != nil {
		return Signature{}, err
	}
	var s fr.Element
	// S is reduced modulo the curve order, which is below r, so canonical.
	if err := s.SetBytesCanonical(sig.S[:]); err != nil {
		return Signature{}, err
	}
	return Signature{R: sig.R, S: s}, nil
}

// FullViewingKey sees and, through the custodian, forfeits; it cannot spend.
type FullViewingKey struct {
	AK twistededwards.PointAffine
	NK fr.Element
}

// IVK returns Poseidon(IVK, ak.x, ak.y, nk), the incoming viewing key, used
// as a scalar as is (not reduced modulo the subgroup order, so the circuit
// and the native side agree).
func (f *FullViewingKey) IVK() fr.Element {
	return poseidon.MustHash(domain.Tag(domain.IVK), f.AK.X, f.AK.Y, f.NK)
}

// Address returns the payment address (d, [ivk]g_d).
func (f *FullViewingKey) Address(d Diversifier) (Address, error) {
	gd, err := d.GroupHash()
	if err != nil {
		return Address{}, err
	}
	ivk := f.IVK()
	var pkd twistededwards.PointAffine
	pkd.ScalarMultiplication(&gd, ivk.BigInt(new(big.Int)))
	return Address{D: d, PKD: pkd}, nil
}

// Address is a diversified payment address.
type Address struct {
	D   Diversifier
	PKD twistededwards.PointAffine
}

// Signature is a spend authorization: an EdDSA signature by ask over a
// message field element.
type Signature struct {
	R twistededwards.PointAffine
	S fr.Element
}

// Vars converts the signature to circuit variables.
func (s *Signature) Vars() gadgeteddsa.Signature {
	var v gadgeteddsa.Signature
	v.R.X, v.R.Y, v.S = s.R.X, s.R.Y, s.S
	return v
}

// Dummy is a placeholder signature for witnesses that are not checked
// (forced burns): the base point and S = 0, both well-formed so the gadget's
// own range and curve assertions pass.
func Dummy() Signature {
	return Signature{R: twistededwards.GetEdwardsCurve().Base}
}

// PointVars converts a point to circuit variables.
func PointVars(p *twistededwards.PointAffine) gadgetted.Point {
	return gadgetted.Point{X: p.X, Y: p.Y}
}

// AKVars converts ak to the EdDSA gadget's public key.
func AKVars(ak *twistededwards.PointAffine) gadgeteddsa.PublicKey {
	return gadgeteddsa.PublicKey{A: PointVars(ak)}
}

// Note is an opened note.
type Note struct {
	Value uint64
	D     Diversifier
	PKD   twistededwards.PointAffine
	R     fr.Element
}

// GD returns g_d = GroupHash(d).
func (n *Note) GD() twistededwards.PointAffine {
	gd, err := n.D.GroupHash()
	if err != nil {
		panic(err)
	}
	return gd
}

// Commitment returns Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r).
func (n *Note) Commitment() fr.Element {
	var v fr.Element
	v.SetUint64(n.Value)
	gd := n.GD()
	return poseidon.MustHash(domain.Tag(domain.CM), v, gd.X, gd.Y, n.PKD.X, n.PKD.Y, n.R)
}

// Nullifier returns Poseidon(NF, nk, cm, index) for the note at leaf index.
func Nullifier(nk, cm fr.Element, index uint64) fr.Element {
	var i fr.Element
	i.SetUint64(index)
	return poseidon.MustHash(domain.Tag(domain.NF), nk, cm, i)
}

// CommitmentGadget constrains and returns Poseidon(CM, value, g_d, pk_d, r).
func CommitmentGadget(api frontend.API, value frontend.Variable, gd, pkd gadgetted.Point, r frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, domain.Tag(domain.CM), value, gd.X, gd.Y, pkd.X, pkd.Y, r)
}

// NullifierGadget constrains and returns Poseidon(NF, nk, cm, index).
func NullifierGadget(api frontend.API, nk, cm, index frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, domain.Tag(domain.NF), nk, cm, index)
}

// IVKGadget constrains and returns Poseidon(IVK, ak.x, ak.y, nk).
func IVKGadget(api frontend.API, ak gadgeteddsa.PublicKey, nk frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, domain.Tag(domain.IVK), ak.A.X, ak.A.Y, nk)
}

// AssertNotSmallOrder constrains p to be on the curve with [8]p ≠ identity,
// so p has a component in the prime-order subgroup and a scalar multiple of
// it binds the scalar modulo the subgroup order. The cofactor is 8, so
// three doublings; a point with [8]p of order 2 would have order 16, which
// the group has none of, so [8]p ≠ identity reduces to [8]p.x ≠ 0.
func AssertNotSmallOrder(curve gadgetted.Curve, p gadgetted.Point) {
	curve.AssertIsOnCurve(p)
	q := curve.Double(curve.Double(curve.Double(p)))
	curve.API().AssertIsDifferent(q.X, 0)
}

// Random returns a note of the given value to addr with fresh r.
func Random(rng io.Reader, value uint64, addr Address) (Note, error) {
	n := Note{Value: value, D: addr.D, PKD: addr.PKD}
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
// fixtures: the owner is SpendingKeyFromSeed(seed), the diversifier and r
// are SHA-256(seed ‖ label).
func FromSeed(seed []byte, value uint64) Note {
	fvk := SpendingKeyFromSeed(seed).FullViewingKey()
	addr, err := fvk.Address(DiversifierFromSeed(seed))
	if err != nil {
		panic(err)
	}
	return Note{Value: value, D: addr.D, PKD: addr.PKD, R: deriveFromSeed(seed, "r")}
}

// DiversifierFromSeed is the diversifier of the notes FromSeed derives.
func DiversifierFromSeed(seed []byte) Diversifier {
	h := sha256.Sum256(append(append([]byte{}, seed...), []byte("d")...))
	var d Diversifier
	copy(d[:], h[:])
	return d
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
// g_d is redundant with d and checked against it.
type Opening struct {
	Value       uint64 `json:"value"`
	Diversifier string `json:"d"`
	GDX         string `json:"g_d_x"`
	GDY         string `json:"g_d_y"`
	PKDX        string `json:"pk_d_x"`
	PKDY        string `json:"pk_d_y"`
	R           string `json:"r"`
	Commitment  string `json:"commitment"`
}

// ToOpening serializes the note and its commitment.
func (n *Note) ToOpening() Opening {
	cm, gd, d := n.Commitment(), n.GD(), n.D.Element()
	return Opening{
		Value:       n.Value,
		Diversifier: Hex32(&d),
		GDX:         Hex32(&gd.X),
		GDY:         Hex32(&gd.Y),
		PKDX:        Hex32(&n.PKD.X),
		PKDY:        Hex32(&n.PKD.Y),
		R:           Hex32(&n.R),
		Commitment:  Hex32(&cm),
	}
}

// FromOpening parses an Opening and checks g_d and the commitment.
func FromOpening(o Opening) (Note, error) {
	n := Note{Value: o.Value}
	var d, gdx, gdy, cm fr.Element
	for _, f := range []struct {
		name string
		src  string
		dst  *fr.Element
	}{
		{"d", o.Diversifier, &d},
		{"g_d_x", o.GDX, &gdx},
		{"g_d_y", o.GDY, &gdy},
		{"pk_d_x", o.PKDX, &n.PKD.X},
		{"pk_d_y", o.PKDY, &n.PKD.Y},
		{"r", o.R, &n.R},
		{"commitment", o.Commitment, &cm},
	} {
		if err := ParseHex32(f.src, f.dst); err != nil {
			return Note{}, fmt.Errorf("note: %s: %w", f.name, err)
		}
	}
	db := d.Bytes()
	for _, b := range db[:fr.Bytes-DiversifierSize] {
		if b != 0 {
			return Note{}, fmt.Errorf("note: d exceeds %d bytes", DiversifierSize)
		}
	}
	copy(n.D[:], db[fr.Bytes-DiversifierSize:])
	if gd := n.GD(); !gd.X.Equal(&gdx) || !gd.Y.Equal(&gdy) {
		return Note{}, fmt.Errorf("note: g_d is not GroupHash(d)")
	}
	if !n.PKD.IsOnCurve() {
		return Note{}, fmt.Errorf("note: pk_d is not on the curve")
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

// HexBytes32 encodes 32 raw bytes as 0x-prefixed hex.
func HexBytes32(b *[32]byte) string {
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
