package client

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/mint"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/transfer"
)

// A whole lifecycle through the wallet API, with the circuits checked by
// the solver (not proved): shield to Alice, Alice pays Bob with change,
// Bob unshields, the custodian reads everything and forfeits Alice's change.
func TestLifecycle(t *testing.T) {
	custodian := encrypt.NewAuditKey(fr.NewElement(5))
	alice := &Wallet{Key: note.SpendingKeyFromSeed([]byte("alice"))}
	bob := &Wallet{Key: note.SpendingKeyFromSeed([]byte("bob"))}
	pool := [32]byte{1}
	var ledger Ledger

	// Two shields to Alice.
	for i, v := range []uint64{1000, 2000} {
		addr, err := alice.Address(note.DiversifierFromSeed([]byte{byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
		sh, err := NewShield(rand.Reader, addr, v, &custodian.PK)
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(&mint.Circuit{}, sh.Circuit, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("shield %d: %v", i, err)
		}
		ledger.Append(sh.Statement.Commitment, sh.EncBlob)
	}
	owned := alice.Scan(&ledger)
	if len(owned) != 2 || owned[0].Note.Value != 1000 || owned[1].Index != 1 {
		t.Fatalf("alice sees %+v", owned)
	}
	if got := bob.Scan(&ledger); len(got) != 0 {
		t.Fatalf("bob sees %+v", got)
	}

	// Alice pays Bob 2500 and keeps 500.
	bobAddr, _ := bob.Address(note.DiversifierFromSeed([]byte("bob-0")))
	change, _ := alice.Address(note.DiversifierFromSeed([]byte("alice-change")))
	tr, err := alice.Pay(rand.Reader, &ledger, pool, &custodian.PK, owned,
		[2]Payment{{To: bobAddr, Value: 2500}, {To: change, Value: 500}})
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(&transfer.Circuit{}, tr.Circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	for _, nf := range tr.Statement.Nullifiers {
		ledger.Spend(nf)
	}
	for i := range tr.Outputs {
		ledger.Append(tr.Statement.Commitments[i], tr.EncBlobs[i])
	}
	if got := alice.Scan(&ledger); len(got) != 1 || got[0].Note.Value != 500 || got[0].Index != 3 {
		t.Fatalf("after paying, alice sees %+v", got)
	}
	bobs := bob.Scan(&ledger)
	if len(bobs) != 1 || bobs[0].Note.Value != 2500 || bobs[0].Index != 2 {
		t.Fatalf("bob sees %+v", bobs)
	}

	// Bob unshields.
	dest := [32]byte{9}
	c, err := bob.Unshield(&ledger, pool, dest, bobs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(&burn.Circuit{}, c, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("unshield: %v", err)
	}

	// The custodian reads the transfer's outputs and forfeits Alice's
	// change with her registered full viewing key.
	epk, cts, err := encrypt.ParseAuditBlob(tr.Statement.AuditBlob)
	if err != nil {
		t.Fatal(err)
	}
	outs, err := custodian.AuditDecrypt(&epk, cts)
	if err != nil {
		t.Fatal(err)
	}
	if outs[1].Value != 500 {
		t.Fatalf("custodian read %+v", outs)
	}
	f, err := Forfeit(&ledger, pool, dest, outs[1], 3, alice.FullViewingKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(&burn.Circuit{}, f, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("forfeit: %v", err)
	}

	// A single-input payment pads with a dummy.
	one, err := bob.Pay(rand.Reader, &ledger, pool, &custodian.PK, bobs,
		[2]Payment{{To: bobAddr, Value: 2500}, {To: bobAddr, Value: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(&transfer.Circuit{}, one.Circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("one-input transfer: %v", err)
	}

	// The same note twice is refused before proving.
	if _, err := bob.Pay(rand.Reader, &ledger, pool, &custodian.PK, []Owned{bobs[0], bobs[0]},
		[2]Payment{{To: bobAddr, Value: 5000}, {To: bobAddr, Value: 0}}); err == nil {
		t.Fatal("double spend accepted")
	}

	// Payments must use the inputs up.
	if _, err := bob.Pay(rand.Reader, &ledger, pool, &custodian.PK, bobs,
		[2]Payment{{To: bobAddr, Value: 1}, {To: bobAddr, Value: 0}}); err == nil {
		t.Fatal("unbalanced payment accepted")
	}
}
