// Package encrypt is note encryption: to the recipient, so they can find
// and spend what they were sent, and to the custodian's audit key, so the
// pool's custodian can read every note in its pool.
//
// Both are Sapling's construction with Poseidon in place of BLAKE2b and
// ChaCha20: an ephemeral Diffie-Hellman on the embedded curve, a KDF of
// the shared secret, a keystream.
//
// # Recipient (off-circuit)
//
//	esk  random scalar
//	epk  = [esk]·g_d            (g_d of the recipient's address)
//	ss   = [esk]·pk_d  = [ivk]·epk
//	key  = Poseidon(KDF, ss.x, ss.y, epk.x, epk.y)
//	ks_i = Poseidon(ENC, key, i)[1:32]        (31 low bytes: the top byte of a field element is biased)
//	blob = epk (32, compressed) ‖ (value LE 8 ‖ d 11 ‖ r 32) ⊕ (ks_0 ‖ ks_1)[0:51]
//
// The recipient trial-decrypts every blob with ivk and keeps the ones
// whose decrypted note recommits to the on-chain commitment; that check
// is the integrity check, as in Sapling, so there is no MAC. Nothing
// constrains the sender to encrypt honestly: a garbage blob only costs the
// sender the payment, as in Zcash.
//
// # Audit (in-circuit)
//
//	esk  random scalar, one per transaction
//	epk  = [esk]·G
//	ss   = [esk]·apk   = [ask]·epk          (apk the custodian's audit key)
//	key  = Poseidon(KDF, ss.x, ss.y, epk.x, epk.y)
//	per output i: p = (packed, pk_d.y, r),  packed = lsb(pk_d.x)·2^152 + value·2^88 + d
//	              c_{3i+j} = p_j + Poseidon(ENC, key, 3i+j)
//	audit_hash = Poseidon(AUDIT, apk.x, apk.y, epk.x, epk.y, c_0, ..., extra...)
//
// The circuit computes all of it from the output notes it also commits to,
// and publishes audit_hash; the program recomputes it from the ciphertext
// in the instruction and the pool's audit key. So the custodian can decrypt
// every note's full opening, which forfeiture needs, and a sender cannot
// put anything else there. pk_d is sent as y plus the parity of x, three
// field elements per note.
package encrypt

import (
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/domain"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Sizes of the recipient blob.
const (
	PlaintextSize     = 8 + note.DiversifierSize + fr.Bytes // value, d, r
	RecipientBlobSize = fr.Bytes + PlaintextSize            // compressed epk ‖ ciphertext
	// AuditElements is the number of ciphertext field elements per note.
	AuditElements = 3
	// ChunkSize is how many bytes of recipient blobs go into one field
	// element of EncHash.
	ChunkSize = 31
)

// RandomScalar draws an ephemeral secret: a uniform field element, used as
// an integer scalar as is (the gadget decomposes the full field width).
func RandomScalar(rng io.Reader) (fr.Element, error) {
	var buf [64]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return fr.Element{}, err
	}
	var e fr.Element
	e.SetBytes(buf[:])
	return e, nil
}

func mul(p *twistededwards.PointAffine, s fr.Element) twistededwards.PointAffine {
	var out twistededwards.PointAffine
	out.ScalarMultiplication(p, s.BigInt(new(big.Int)))
	return out
}

func kdf(ss, epk *twistededwards.PointAffine) fr.Element {
	return poseidon.MustHash(domain.Tag(domain.KDF), ss.X, ss.Y, epk.X, epk.Y)
}

func keystream(key fr.Element, i uint64) fr.Element {
	var c fr.Element
	c.SetUint64(i)
	return poseidon.MustHash(domain.Tag(domain.ENC), key, c)
}

// EncryptNote encrypts n to its own address with a fresh ephemeral key.
func EncryptNote(rng io.Reader, n *note.Note) ([RecipientBlobSize]byte, error) {
	esk, err := RandomScalar(rng)
	if err != nil {
		return [RecipientBlobSize]byte{}, err
	}
	return EncryptNoteWith(esk, n), nil
}

// EncryptNoteWith is EncryptNote with a given ephemeral secret.
func EncryptNoteWith(esk fr.Element, n *note.Note) [RecipientBlobSize]byte {
	gd := n.GD()
	epk := mul(&gd, esk)
	ss := mul(&n.PKD, esk)
	key := kdf(&ss, &epk)

	var blob [RecipientBlobSize]byte
	c := epk.Bytes()
	copy(blob[:fr.Bytes], c[:])
	pt := blob[fr.Bytes:]
	for i := 0; i < 8; i++ {
		pt[i] = byte(n.Value >> (8 * i))
	}
	copy(pt[8:], n.D[:])
	r := n.R.Bytes()
	copy(pt[8+note.DiversifierSize:], r[:])
	xorKeystream(pt, key)
	return blob
}

// KeystreamBytes is how many bytes each keystream element yields: its 31
// low bytes. The top byte of a canonical element is biased (always below
// 0x31), so it is dropped.
const KeystreamBytes = fr.Bytes - 1

func xorKeystream(buf []byte, key fr.Element) {
	for i := 0; i*KeystreamBytes < len(buf); i++ {
		k := keystream(key, uint64(i))
		ks := k.Bytes()
		for j := 0; j < KeystreamBytes && i*KeystreamBytes+j < len(buf); j++ {
			buf[i*KeystreamBytes+j] ^= ks[1+j]
		}
	}
}

// DecryptNote trial-decrypts blob with fvk and returns the note if it
// recommits to cm. The note's pk_d is derived from d with ivk, so a note
// addressed to someone else fails the commitment check.
func DecryptNote(fvk *note.FullViewingKey, blob []byte, cm fr.Element) (note.Note, bool) {
	if len(blob) != RecipientBlobSize {
		return note.Note{}, false
	}
	var epk twistededwards.PointAffine
	if _, err := epk.SetBytes(blob[:fr.Bytes]); err != nil || !epk.IsOnCurve() {
		return note.Note{}, false
	}
	ss := mul(&epk, fvk.IVK())
	key := kdf(&ss, &epk)
	var pt [PlaintextSize]byte
	copy(pt[:], blob[fr.Bytes:])
	xorKeystream(pt[:], key)

	n := note.Note{}
	for i := 0; i < 8; i++ {
		n.Value |= uint64(pt[i]) << (8 * i)
	}
	copy(n.D[:], pt[8:8+note.DiversifierSize])
	if err := n.R.SetBytesCanonical(pt[8+note.DiversifierSize:]); err != nil {
		return note.Note{}, false
	}
	addr, err := fvk.Address(n.D)
	if err != nil {
		return note.Note{}, false
	}
	n.PKD = addr.PKD
	if got := n.Commitment(); !got.Equal(&cm) {
		return note.Note{}, false
	}
	return n, true
}

// EncHash binds recipient blobs into one field element: the concatenation
// in 31-byte big-endian chunks, zero-padded, under ENCH. The program
// recomputes it from the instruction data.
func EncHash(blobs ...[]byte) fr.Element {
	var all []byte
	for _, b := range blobs {
		all = append(all, b...)
	}
	n := (len(all) + ChunkSize - 1) / ChunkSize
	inputs := make([]fr.Element, 0, n+1)
	inputs = append(inputs, domain.Tag(domain.ENCH))
	for i := 0; i < n; i++ {
		var chunk [ChunkSize]byte
		copy(chunk[:], all[i*ChunkSize:])
		var e fr.Element
		e.SetBytes(chunk[:])
		inputs = append(inputs, e)
	}
	return poseidon.MustHash(inputs...)
}

// AuditKey is the custodian's decryption key.
type AuditKey struct {
	sk fr.Element
	PK twistededwards.PointAffine
}

// NewAuditKey derives the key pair from a secret scalar.
func NewAuditKey(sk fr.Element) AuditKey {
	base := twistededwards.GetEdwardsCurve().Base
	return AuditKey{sk: sk, PK: mul(&base, sk)}
}

// Packed is the first audit plaintext element of a note:
// lsb(pk_d.x)·2^152 + value·2^88 + d.
func Packed(n *note.Note) fr.Element {
	var packed big.Int
	if lsb(&n.PKD.X) == 1 {
		packed.SetBit(&packed, 152, 1)
	}
	var v big.Int
	v.SetUint64(n.Value)
	v.Lsh(&v, 88)
	packed.Add(&packed, &v)
	var d big.Int
	d.SetBytes(n.D[:])
	packed.Add(&packed, &d)
	var e fr.Element
	e.SetBigInt(&packed)
	return e
}

// Plaintext is the audit plaintext of one note: (packed, pk_d.y, r).
func Plaintext(n *note.Note) [AuditElements]fr.Element {
	return [AuditElements]fr.Element{Packed(n), n.PKD.Y, n.R}
}

// AuditEncrypt encrypts the notes to apk with ephemeral secret esk and
// returns epk and the ciphertext elements, AuditElements per note.
func AuditEncrypt(esk fr.Element, apk *twistededwards.PointAffine, notes ...*note.Note) (twistededwards.PointAffine, []fr.Element) {
	base := twistededwards.GetEdwardsCurve().Base
	epk := mul(&base, esk)
	ss := mul(apk, esk)
	key := kdf(&ss, &epk)
	cts := make([]fr.Element, 0, AuditElements*len(notes))
	for _, n := range notes {
		pt := Plaintext(n)
		for j := range pt {
			ks := keystream(key, uint64(len(cts)))
			var c fr.Element
			c.Add(&pt[j], &ks)
			cts = append(cts, c)
		}
	}
	return epk, cts
}

// AuditDecrypt recovers the notes from epk and the ciphertext elements.
// It fails if a plaintext is malformed (which a proof rules out).
func (k *AuditKey) AuditDecrypt(epk *twistededwards.PointAffine, cts []fr.Element) ([]note.Note, error) {
	if len(cts)%AuditElements != 0 {
		return nil, fmt.Errorf("encrypt: %d ciphertext elements", len(cts))
	}
	ss := mul(epk, k.sk)
	key := kdf(&ss, epk)
	notes := make([]note.Note, 0, len(cts)/AuditElements)
	for i := 0; i < len(cts); i += AuditElements {
		var pt [AuditElements]fr.Element
		for j := range pt {
			ks := keystream(key, uint64(i+j))
			pt[j].Sub(&cts[i+j], &ks)
		}
		n, err := unpack(pt)
		if err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, nil
}

func unpack(pt [AuditElements]fr.Element) (note.Note, error) {
	var packed big.Int
	pt[0].BigInt(&packed)
	if packed.BitLen() > 153 {
		return note.Note{}, fmt.Errorf("encrypt: packed element out of range")
	}
	sign := packed.Bit(152)
	packed.SetBit(&packed, 152, 0)
	var n note.Note
	var d big.Int
	d.Mod(&packed, new(big.Int).Lsh(big.NewInt(1), 88))
	db := d.FillBytes(make([]byte, note.DiversifierSize))
	copy(n.D[:], db)
	packed.Rsh(&packed, 88)
	if !packed.IsUint64() {
		return note.Note{}, fmt.Errorf("encrypt: value out of range")
	}
	n.Value = packed.Uint64()
	n.PKD.Y = pt[1]
	n.R = pt[2]
	x, ok := xFromY(n.PKD.Y)
	if !ok {
		return note.Note{}, fmt.Errorf("encrypt: pk_d.y is not on the curve")
	}
	if lsb(&x) != sign {
		x.Neg(&x)
	}
	n.PKD.X = x
	return n, nil
}

// lsb is the least significant bit of the canonical integer of e.
func lsb(e *fr.Element) uint {
	return uint(e.BigInt(new(big.Int)).Bit(0))
}

// xFromY solves a x² + y² = 1 + D x² y² for x, returning either root.
func xFromY(y fr.Element) (fr.Element, bool) {
	params := twistededwards.GetEdwardsCurve()
	one := fr.NewElement(1)
	var yy, num, den, x fr.Element
	yy.Square(&y)
	num.Sub(&one, &yy)
	den.Mul(&params.D, &yy)
	den.Sub(&params.A, &den)
	if den.IsZero() {
		return fr.Element{}, false
	}
	x.Div(&num, &den)
	if x.Sqrt(&x) == nil {
		return fr.Element{}, false
	}
	return x, true
}

// AuditHash is Poseidon(AUDIT, apk.x, apk.y, epk.x, epk.y, cts..., extra...).
func AuditHash(apk, epk *twistededwards.PointAffine, cts []fr.Element, extra ...fr.Element) fr.Element {
	inputs := []fr.Element{domain.Tag(domain.AUDIT), apk.X, apk.Y, epk.X, epk.Y}
	inputs = append(inputs, cts...)
	inputs = append(inputs, extra...)
	return poseidon.MustHash(inputs...)
}

// OutputVars is an output note as the audit gadget needs it. Value must be
// range-checked to 64 bits and D to 88 by the caller.
type OutputVars struct {
	GD, PKD gadgetted.Point
	R       frontend.Variable
	Value   frontend.Variable
	D       frontend.Variable
}

// AuditGadget constrains the audit ciphertext of the outputs under apk with
// ephemeral secret esk and returns audit_hash. extra is appended to the
// hash, for statements that bind more (C_mint binds the recipient blob).
func AuditGadget(api frontend.API, curve gadgetted.Curve, apk gadgetted.Point, esk frontend.Variable, outputs []OutputVars, extra ...frontend.Variable) (frontend.Variable, error) {
	base := gadgetted.Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	// Complete double-and-add (see burn.go on why not ScalarMul).
	epk := curve.DoubleBaseScalarMul(base, base, esk, 0)
	ss := curve.DoubleBaseScalarMul(apk, apk, esk, 0)
	key, err := poseidon.HashGadget(api, domain.Tag(domain.KDF), ss.X, ss.Y, epk.X, epk.Y)
	if err != nil {
		return nil, err
	}
	inputs := []frontend.Variable{domain.Tag(domain.AUDIT), apk.X, apk.Y, epk.X, epk.Y}
	for i, o := range outputs {
		xbits := api.ToBinary(o.PKD.X)
		shift152 := new(big.Int).Lsh(big.NewInt(1), 152)
		shift88 := new(big.Int).Lsh(big.NewInt(1), 88)
		packed := api.Add(api.Mul(xbits[0], shift152), api.Mul(o.Value, shift88), o.D)
		for j, p := range []frontend.Variable{packed, o.PKD.Y, o.R} {
			ks, err := poseidon.HashGadget(api, domain.Tag(domain.ENC), key, AuditElements*i+j)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, api.Add(p, ks))
		}
	}
	inputs = append(inputs, extra...)
	return poseidon.HashGadget(api, inputs...)
}

// AuditBlob serializes epk and the ciphertext elements as the instruction
// carries them: epk.x ‖ epk.y ‖ c_0 ‖ ... (32 bytes each, big-endian).
func AuditBlob(epk *twistededwards.PointAffine, cts []fr.Element) []byte {
	out := make([]byte, 0, (2+len(cts))*fr.Bytes)
	for _, e := range append([]fr.Element{epk.X, epk.Y}, cts...) {
		b := e.Bytes()
		out = append(out, b[:]...)
	}
	return out
}

// ParseAuditBlob is the inverse of AuditBlob.
func ParseAuditBlob(blob []byte) (twistededwards.PointAffine, []fr.Element, error) {
	if len(blob) < 2*fr.Bytes || len(blob)%fr.Bytes != 0 {
		return twistededwards.PointAffine{}, nil, fmt.Errorf("encrypt: audit blob of %d bytes", len(blob))
	}
	var epk twistededwards.PointAffine
	if err := epk.X.SetBytesCanonical(blob[:fr.Bytes]); err != nil {
		return twistededwards.PointAffine{}, nil, err
	}
	if err := epk.Y.SetBytesCanonical(blob[fr.Bytes : 2*fr.Bytes]); err != nil {
		return twistededwards.PointAffine{}, nil, err
	}
	var cts []fr.Element
	for i := 2 * fr.Bytes; i < len(blob); i += fr.Bytes {
		var e fr.Element
		if err := e.SetBytesCanonical(blob[i : i+fr.Bytes]); err != nil {
			return twistededwards.PointAffine{}, nil, err
		}
		cts = append(cts, e)
	}
	return epk, cts, nil
}
