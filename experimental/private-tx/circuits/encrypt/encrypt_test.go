package encrypt

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

func TestRecipientRoundTrip(t *testing.T) {
	alice := note.SpendingKeyFromSeed([]byte("alice")).FullViewingKey()
	bob := note.SpendingKeyFromSeed([]byte("bob")).FullViewingKey()
	addr, err := alice.Address(note.DiversifierFromSeed([]byte("a1")))
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Random(rand.Reader, 1_234_567, addr)
	if err != nil {
		t.Fatal(err)
	}
	cm := n.Commitment()
	blob, err := EncryptNote(rand.Reader, &n)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := DecryptNote(&alice, blob[:], cm)
	if !ok {
		t.Fatal("alice cannot decrypt her note")
	}
	if got != n {
		t.Fatal("decrypted note differs")
	}
	if _, ok := DecryptNote(&bob, blob[:], cm); ok {
		t.Fatal("bob decrypted alice's note")
	}
	// Against another commitment the blob is rejected.
	var other fr.Element
	other.Add(&cm, new(fr.Element).SetOne())
	if _, ok := DecryptNote(&alice, blob[:], other); ok {
		t.Fatal("decryption accepted a foreign commitment")
	}
	// A flipped ciphertext byte is rejected.
	tampered := blob
	tampered[RecipientBlobSize-1] ^= 1
	if _, ok := DecryptNote(&alice, tampered[:], cm); ok {
		t.Fatal("tampered blob accepted")
	}
	// An epk with a small-order component is rejected, even when the blob
	// is encrypted under the shared secret the recipient would derive.
	esk := fr.NewElement(5)
	mixed := EncryptNoteWith(esk, &n)
	gd := n.GD()
	epk := mul(&gd, esk)
	ss := mul(&n.PKD, esk)
	xorKeystream(mixed[fr.Bytes:], kdf(&ss, &epk)) // back to the plaintext
	var order2 twistededwards.PointAffine
	order2.Y.SetOne()
	order2.Y.Neg(&order2.Y)
	epk.Add(&epk, &order2)
	if !epk.IsOnCurve() || epk.IsInSubGroup() {
		t.Fatal("test point should be on the curve, outside the subgroup")
	}
	ss = mul(&epk, alice.IVK())
	eb := epk.Bytes()
	copy(mixed[:fr.Bytes], eb[:])
	xorKeystream(mixed[fr.Bytes:], kdf(&ss, &epk))
	if _, ok := DecryptNote(&alice, mixed[:], cm); ok {
		t.Fatal("epk outside the prime-order subgroup accepted")
	}
	// So is the identity.
	var zero twistededwards.PointAffine
	zero.Y.SetOne()
	zb := zero.Bytes()
	copy(mixed[:fr.Bytes], zb[:])
	if _, ok := DecryptNote(&alice, mixed[:], cm); ok {
		t.Fatal("identity epk accepted")
	}
	// Two encryptions of the same note differ (fresh esk).
	blob2, _ := EncryptNote(rand.Reader, &n)
	if blob == blob2 {
		t.Fatal("encryption is deterministic across calls")
	}
}

func TestAuditRoundTrip(t *testing.T) {
	var ask fr.Element
	ask.SetUint64(777)
	custodian := NewAuditKey(ask)
	notes := []*note.Note{
		ptr(note.FromSeed([]byte("n0"), 5)),
		ptr(note.FromSeed([]byte("n1"), 1<<63)),
	}
	esk, err := RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epk, cts := AuditEncrypt(esk, &custodian.PK, notes...)
	if len(cts) != 2*AuditElements {
		t.Fatalf("%d ciphertext elements", len(cts))
	}
	got, err := custodian.AuditDecrypt(&epk, cts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range notes {
		if *got[i] != *notes[i] {
			t.Fatalf("note %d: decrypted %+v, want %+v", i, got[i], *notes[i])
		}
	}
	// Another custodian cannot.
	var other fr.Element
	other.SetUint64(778)
	wrong := NewAuditKey(other)
	if dec, err := wrong.AuditDecrypt(&epk, cts); err == nil && *dec[0] == *notes[0] {
		t.Fatal("wrong key decrypted")
	}
	// A note whose pk_d.y has no curve point is reported alone.
	bad := *notes[0]
	for {
		if _, ok := xFromY(bad.PKD.Y); !ok {
			break
		}
		bad.PKD.Y.Add(&bad.PKD.Y, new(fr.Element).SetOne())
	}
	epkBad, ctsBad := AuditEncrypt(esk, &custodian.PK, &bad, notes[1])
	got, err = custodian.AuditDecrypt(&epkBad, ctsBad)
	if err == nil || len(got) != 2 || got[0] != nil {
		t.Fatalf("malformed note not reported: %v, %v", got, err)
	}
	if got[1] == nil || *got[1] != *notes[1] {
		t.Fatal("a malformed note hid the others")
	}
	// Blob round trip.
	blob := AuditBlob(&epk, cts)
	epk2, cts2, err := ParseAuditBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !epk2.Equal(&epk) || len(cts2) != len(cts) || !cts2[5].Equal(&cts[5]) {
		t.Fatal("audit blob round trip")
	}
}

func TestEncHashBindsEveryByte(t *testing.T) {
	a := make([]byte, 2*RecipientBlobSize)
	for i := range a {
		a[i] = byte(i)
	}
	base, err := EncHash(a[:RecipientBlobSize], a[RecipientBlobSize:])
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 30, 31, 82, 83, 2*RecipientBlobSize - 1} {
		b := append([]byte{}, a...)
		b[i] ^= 1
		if h, err := EncHash(b); err != nil || h.Equal(&base) {
			t.Fatalf("byte %d not bound", i)
		}
	}
	if h, err := EncHash(a); err != nil || !h.Equal(&base) {
		t.Fatal("hash depends on how the blobs are split")
	}
}

func TestHashWidthErrors(t *testing.T) {
	// 11 chunks plus the tag fit; 12 do not.
	if _, err := EncHash(make([]byte, 11*ChunkSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := EncHash(make([]byte, 11*ChunkSize+1)); err == nil {
		t.Fatal("EncHash accepted more chunks than Poseidon takes")
	}
	var p twistededwards.PointAffine
	if _, err := AuditHash(&p, &p, make([]fr.Element, 2*AuditElements), fr.Element{}); err != nil {
		t.Fatal(err)
	}
	if _, err := AuditHash(&p, &p, make([]fr.Element, 3*AuditElements)); err == nil {
		t.Fatal("AuditHash accepted more elements than Poseidon takes")
	}
}

type auditCircuit struct {
	AuditHash frontend.Variable `gnark:",public"`
	APK       gadgetted.Point
	ESK       frontend.Variable
	Outputs   [2]OutputVars
}

func (c *auditCircuit) Define(api frontend.API) error {
	curve, err := gadgetted.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	for _, o := range c.Outputs {
		api.ToBinary(o.Value, 64)
		api.ToBinary(o.D, 88)
	}
	h, err := AuditGadget(api, curve, c.APK, c.ESK, c.Outputs[:])
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.AuditHash)
	return nil
}

func outputVars(n *note.Note) OutputVars {
	gd := n.GD()
	return OutputVars{
		GD:    note.PointVars(&gd),
		PKD:   note.PointVars(&n.PKD),
		R:     n.R,
		Value: n.Value,
		D:     n.D.Element(),
	}
}

func TestAuditGadgetMatchesNative(t *testing.T) {
	var ask fr.Element
	ask.SetUint64(99)
	custodian := NewAuditKey(ask)
	n0, n1 := note.FromSeed([]byte("g0"), 42), note.FromSeed([]byte("g1"), 0)
	var esk fr.Element
	esk.SetUint64(123456789)
	epk, cts := AuditEncrypt(esk, &custodian.PK, &n0, &n1)
	h, err := AuditHash(&custodian.PK, &epk, cts)
	if err != nil {
		t.Fatal(err)
	}

	valid := &auditCircuit{
		AuditHash: h,
		APK:       note.PointVars(&custodian.PK),
		ESK:       esk,
		Outputs:   [2]OutputVars{outputVars(&n0), outputVars(&n1)},
	}
	// Any change to a note changes the hash.
	wrongValue := *valid
	wrongValue.Outputs[0].Value = 43
	wrongESK := *valid
	wrongESK.ESK = 1
	// A pk_d off the curve is rejected even with its matching hash.
	off := n1
	off.PKD.Y.Add(&off.PKD.Y, new(fr.Element).SetOne())
	if off.PKD.IsOnCurve() {
		t.Fatal("test pk_d should be off the curve")
	}
	epkOff, ctsOff := AuditEncrypt(esk, &custodian.PK, &n0, &off)
	hOff, err := AuditHash(&custodian.PK, &epkOff, ctsOff)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := *valid
	offCurve.AuditHash = hOff
	offCurve.Outputs[1] = outputVars(&off)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&auditCircuit{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(&wrongValue),
		test.WithInvalidAssignment(&wrongESK),
		test.WithInvalidAssignment(&offCurve),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
	)
	// And the custodian can read what the circuit committed to.
	got, err := custodian.AuditDecrypt(&epk, cts)
	if err != nil {
		t.Fatal(err)
	}
	if *got[0] != n0 || *got[1] != n1 {
		t.Fatal("decrypted notes differ from the circuit's outputs")
	}
}

func ptr(n note.Note) *note.Note { return &n }
