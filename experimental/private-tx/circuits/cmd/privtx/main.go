// privtx builds circuits, keys and proofs for the private-tx protocol.
//
//	privtx smoke-fixture   [-out DIR]
//	privtx mint-fixture    [-out DIR] [-value N] [-seed STRING]
//	privtx burn-fixture    [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]
//	privtx pool-fixture    [-out DIR] [-notes N] [-seed STRING]
//
// Each fixture subcommand compiles its circuit(s), runs a (development) Groth16
// setup, proves fixed witnesses, self-verifies, and writes vk.bin,
// proof*.bin and public*.bin in gnark's native encodings into DIR for the
// Rust e2e tests, plus a JSON file describing the witnesses so the e2e crate
// can recompute every hash with its own Poseidon.
//
// smoke-fixture proves 3·5 = 15. mint-fixture proves one shield.
// burn-fixture fills a tree with N notes and burns one. pool-fixture is a
// whole pool lifecycle built through the client package: N shields to
// Alice, a transfer paying Bob with change, then an unshield by Alice, a
// forfeiture by the custodian and an unshield by Bob, all with the
// ciphertexts the Rust indexer and wallets decrypt.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/client"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/export"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/mint"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/smoke"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/transfer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "smoke-fixture":
		err = smokeFixture(os.Args[2:])
	case "mint-fixture":
		err = mintFixture(os.Args[2:])
	case "burn-fixture":
		err = burnFixture(os.Args[2:])
	case "pool-fixture":
		err = poolFixture(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: privtx smoke-fixture [-out DIR]")
	fmt.Fprintln(os.Stderr, "       privtx mint-fixture [-out DIR] [-value N] [-seed STRING]")
	fmt.Fprintln(os.Stderr, "       privtx burn-fixture [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]")
	fmt.Fprintln(os.Stderr, "       privtx pool-fixture [-out DIR] [-notes N] [-seed STRING]")
	os.Exit(2)
}

// Fixture addresses and keys: fixed so the signed sighashes are
// reproducible; the e2e tests use these values.
var (
	fixturePool        = fixtureAddress("private-tx fixture: pool")
	fixtureDestination = fixtureAddress("private-tx fixture: destination")
	fixtureCustodian   = encrypt.NewAuditKey(fixtureScalar("private-tx fixture: audit key"))
)

func fixtureAddress(label string) [32]byte {
	return sha256.Sum256([]byte(label))
}

func fixtureScalar(label string) fr.Element {
	h := sha256.Sum256([]byte(label))
	var e fr.Element
	e.SetBytes(h[:])
	return e
}

// seededReader is a deterministic io.Reader: SHA-256 counter mode.
type seededReader struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newSeededReader(seed string) *seededReader { return &seededReader{seed: []byte(seed)} }

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			h := sha256.New()
			h.Write(r.seed)
			var c [8]byte
			for i := 0; i < 8; i++ {
				c[i] = byte(r.ctr >> (8 * i))
			}
			h.Write(c[:])
			r.ctr++
			r.buf = h.Sum(nil)
		}
		k := copy(p[n:], r.buf)
		r.buf = r.buf[k:]
		n += k
	}
	return n, nil
}

func smokeFixture(args []string) error {
	fs := flag.NewFlagSet("smoke-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/smoke", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ccs, err := smoke.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	return proveAndWrite("smoke", ccs, smoke.Assignment(3, 5), *out)
}

// mintFixtureFile is note.json: the shielded note, its ciphertexts and the
// hashes the program recomputes.
type mintFixtureFile struct {
	Note      note.Opening `json:"note"`
	AuditPKX  string       `json:"audit_pk_x"`
	AuditPKY  string       `json:"audit_pk_y"`
	AuditBlob string       `json:"audit_blob"`
	EncBlob   string       `json:"enc_blob"`
	AuditHash string       `json:"audit_hash"`
	EncHash   string       `json:"enc_hash"`
}

func mintFixture(args []string) error {
	fs := flag.NewFlagSet("mint-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/mint", "output directory")
	value := fs.Uint64("value", 1_000_000, "note value")
	seed := fs.String("seed", "private-tx mint fixture", "seed for the deterministic note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ccs, err := mint.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	w := client.Wallet{Key: note.SpendingKeyFromSeed([]byte(*seed))}
	addr, err := w.Address(note.DiversifierFromSeed([]byte(*seed)))
	if err != nil {
		return err
	}
	sh, err := client.NewShield(newSeededReader(*seed), addr, *value, &fixtureCustodian.PK)
	if err != nil {
		return err
	}
	if err := proveAndWrite("C_mint", ccs, sh.Circuit, *out); err != nil {
		return err
	}
	file := mintFixtureFile{
		Note:      sh.Note.ToOpening(),
		AuditPKX:  note.Hex32(&fixtureCustodian.PK.X),
		AuditPKY:  note.Hex32(&fixtureCustodian.PK.Y),
		AuditBlob: hexBytes(sh.Statement.AuditBlob),
		EncBlob:   hexBytes(sh.EncBlob),
		AuditHash: note.Hex32(&sh.Statement.AuditHash),
		EncHash:   note.Hex32(&sh.Statement.EncHash),
	}
	if err := writeJSON(filepath.Join(*out, "note.json"), file); err != nil {
		return err
	}
	fmt.Printf("commitment %s\n", file.Note.Commitment)
	return nil
}

// burnFixtureFile is burn.json: enough for the e2e crate to rebuild the tree,
// the nullifier and the sighash with its own Poseidon.
type burnFixtureFile struct {
	Depth       int          `json:"depth"`
	Leaves      []string     `json:"leaves"`
	Index       uint64       `json:"index"`
	Note        note.Opening `json:"note"`
	Root        string       `json:"root"`
	Nullifier   string       `json:"nullifier"`
	Forced      bool         `json:"forced"`
	NK          string       `json:"nk"`
	Pool        string       `json:"pool"`
	Destination string       `json:"destination"`
	SigHash     string       `json:"sighash"`
}

func burnFixture(args []string) error {
	fs := flag.NewFlagSet("burn-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/burn", "output directory")
	count := fs.Uint("notes", 5, "number of notes in the tree")
	index := fs.Uint64("index", 2, "leaf index of the note to burn")
	forced := fs.Bool("forced", false, "burn as the custodian (forfeiture) instead of the owner")
	seed := fs.String("seed", "private-tx burn fixture", "seed for the deterministic notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *index >= uint64(*count) {
		return fmt.Errorf("index %d out of range (%d notes)", *index, *count)
	}
	ccs, err := burn.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	var tr merkle.Tree
	notes := make([]note.Note, *count)
	seeds := make([][]byte, *count)
	file := burnFixtureFile{Depth: merkle.Depth, Index: *index, Forced: *forced}
	for i := range notes {
		seeds[i] = []byte(fmt.Sprintf("%s/%d", *seed, i))
		notes[i] = note.FromSeed(seeds[i], 1_000_000*uint64(i+1))
		cm := notes[i].Commitment()
		if _, err := tr.Append(cm); err != nil {
			return err
		}
		file.Leaves = append(file.Leaves, note.Hex32(&cm))
	}
	path, err := tr.Path(*index)
	if err != nil {
		return err
	}
	n, key := notes[*index], note.SpendingKeyFromSeed(seeds[*index])
	fvk := key.FullViewingKey()
	var w *burn.Circuit
	if *forced {
		w = burn.Forfeit(&n, &path, fvk, fixturePool, fixtureDestination)
	} else {
		w, err = burn.Unshield(&n, &path, key, fixturePool, fixtureDestination)
		if err != nil {
			return err
		}
	}
	if err := proveAndWrite("C_burn", ccs, w, *out); err != nil {
		return err
	}
	root, nf := tr.Root(), note.Nullifier(fvk.NK, n.Commitment(), *index)
	sh := burn.SigHash(fixturePool, fixtureDestination, nf, n.Value)
	file.Note, file.Root, file.Nullifier = n.ToOpening(), note.Hex32(&root), note.Hex32(&nf)
	file.NK = note.Hex32(&fvk.NK)
	file.Pool, file.Destination, file.SigHash = note.HexBytes32(&fixturePool), note.HexBytes32(&fixtureDestination), note.Hex32(&sh)
	if err := writeJSON(filepath.Join(*out, "burn.json"), file); err != nil {
		return err
	}
	fmt.Printf("root %s\nnullifier %s\nforced %v\n", file.Root, file.Nullifier, *forced)
	return nil
}

// poolFixtureFile is pool.json: a pool lifecycle. Proof files sit next to
// it: mint/vk.bin with mint/proof-<i>.bin, mint/public-<i>.bin per shield;
// transfer/vk.bin, transfer/proof.bin, transfer/public.bin; burn/vk.bin
// with burn/proof-<name>.bin, burn/public-<name>.bin per burn.
type poolFixtureFile struct {
	Depth       int                 `json:"depth"`
	Pool        string              `json:"pool"`
	Destination string              `json:"destination"`
	Custodian   poolCustodian       `json:"custodian"`
	Wallets     map[string]poolKeys `json:"wallets"`
	Mints       []poolMint          `json:"mints"`
	Transfer    poolTransfer        `json:"transfer"`
	Leaves      []string            `json:"leaves"`
	Root        string              `json:"root"`
	Burns       []poolBurn          `json:"burns"`
}

type poolCustodian struct {
	AuditSK  string `json:"audit_sk"`
	AuditPKX string `json:"audit_pk_x"`
	AuditPKY string `json:"audit_pk_y"`
}

// poolKeys is a wallet's full viewing key and ivk: what the Rust indexer
// scans with.
type poolKeys struct {
	AKX string `json:"ak_x"`
	AKY string `json:"ak_y"`
	NK  string `json:"nk"`
	IVK string `json:"ivk"`
}

type poolMint struct {
	Note      note.Opening `json:"note"`
	AuditBlob string       `json:"audit_blob"`
	EncBlob   string       `json:"enc_blob"`
	AuditHash string       `json:"audit_hash"`
}

type poolTransfer struct {
	Root        string         `json:"root"`
	Inputs      []uint64       `json:"inputs"`
	Nullifiers  []string       `json:"nullifiers"`
	Commitments []string       `json:"commitments"`
	Outputs     []note.Opening `json:"outputs"`
	Recipients  []string       `json:"recipients"`
	AuditBlob   string         `json:"audit_blob"`
	EncBlobs    []string       `json:"enc_blobs"`
	AuditHash   string         `json:"audit_hash"`
	EncHash     string         `json:"enc_hash"`
	SigHash     string         `json:"sighash"`
}

type poolBurn struct {
	Name        string   `json:"name"`
	Owner       string   `json:"owner"`
	Index       uint64   `json:"index"`
	Nullifier   string   `json:"nullifier"`
	Forced      bool     `json:"forced"`
	NK          string   `json:"nk"`
	Destination string   `json:"destination"`
	SigHash     string   `json:"sighash"`
	Siblings    []string `json:"siblings"`
}

func keysOf(w *client.Wallet) poolKeys {
	fvk := w.FullViewingKey()
	ivk := fvk.IVK()
	return poolKeys{AKX: note.Hex32(&fvk.AK.X), AKY: note.Hex32(&fvk.AK.Y), NK: note.Hex32(&fvk.NK), IVK: note.Hex32(&ivk)}
}

func poolFixture(args []string) error {
	fs := flag.NewFlagSet("pool-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/pool", "output directory")
	count := fs.Uint("notes", 5, "number of notes to shield")
	seed := fs.String("seed", "private-tx pool fixture", "seed for the deterministic keys and notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *count < 5 {
		return fmt.Errorf("need at least 5 notes (two spent, one unshielded, one forfeited)")
	}
	rng := newSeededReader(*seed)

	mintProver, err := client.NewProver("C_mint", mint.Compile)
	if err != nil {
		return err
	}
	transferProver, err := client.NewProver("C_transfer", transfer.Compile)
	if err != nil {
		return err
	}
	burnProver, err := client.NewProver("C_burn", burn.Compile)
	if err != nil {
		return err
	}
	for _, p := range []*client.Prover{mintProver, transferProver, burnProver} {
		fmt.Printf("%s: %d constraints, %d public inputs\n", p.Name, p.CCS.GetNbConstraints(), p.CCS.GetNbPublicVariables()-1)
	}
	mintDir, transferDir, burnDir := filepath.Join(*out, "mint"), filepath.Join(*out, "transfer"), filepath.Join(*out, "burn")
	for _, d := range []struct {
		dir string
		p   *client.Prover
	}{{mintDir, mintProver}, {transferDir, transferProver}, {burnDir, burnProver}} {
		sizes, err := export.WriteVK(d.dir, "vk.bin", d.p.VK)
		if err != nil {
			return err
		}
		report(d.dir, sizes)
	}

	alice := &client.Wallet{Key: note.SpendingKeyFromSeed([]byte(*seed + "/alice"))}
	bob := &client.Wallet{Key: note.SpendingKeyFromSeed([]byte(*seed + "/bob"))}
	custodian := fixtureCustodian
	var ledger client.Ledger
	file := poolFixtureFile{
		Depth:       merkle.Depth,
		Pool:        note.HexBytes32(&fixturePool),
		Destination: note.HexBytes32(&fixtureDestination),
		Custodian: poolCustodian{
			AuditSK:  note.Hex32(ptr(fixtureScalar("private-tx fixture: audit key"))),
			AuditPKX: note.Hex32(&custodian.PK.X),
			AuditPKY: note.Hex32(&custodian.PK.Y),
		},
		Wallets: map[string]poolKeys{"alice": keysOf(alice), "bob": keysOf(bob)},
	}

	// Shields to Alice.
	for i := uint(0); i < *count; i++ {
		addr, err := alice.Address(note.DiversifierFromSeed([]byte(fmt.Sprintf("%s/alice/%d", *seed, i))))
		if err != nil {
			return err
		}
		sh, err := client.NewShield(rng, addr, 1_000_000*uint64(i+1), &custodian.PK)
		if err != nil {
			return err
		}
		if err := prove(mintProver, mintDir, fmt.Sprint(i), sh.Circuit); err != nil {
			return err
		}
		ledger.Append(sh.Statement.Commitment, sh.EncBlob)
		file.Mints = append(file.Mints, poolMint{
			Note:      sh.Note.ToOpening(),
			AuditBlob: hexBytes(sh.Statement.AuditBlob),
			EncBlob:   hexBytes(sh.EncBlob),
			AuditHash: note.Hex32(&sh.Statement.AuditHash),
		})
	}

	// Alice scans, then pays Bob with notes 0 and 1 and keeps the change.
	owned := alice.Scan(&ledger)
	if len(owned) != int(*count) {
		return fmt.Errorf("alice sees %d notes, want %d", len(owned), *count)
	}
	bobAddr, err := bob.Address(note.DiversifierFromSeed([]byte(*seed + "/bob/0")))
	if err != nil {
		return err
	}
	change, err := alice.Address(note.DiversifierFromSeed([]byte(*seed + "/alice/change")))
	if err != nil {
		return err
	}
	spends := owned[:2]
	total := spends[0].Note.Value + spends[1].Note.Value
	toBob := total*5/6 - total*5/6%1000 // 2.5M of 3M
	tr, err := alice.Pay(rng, &ledger, fixturePool, &custodian.PK, spends,
		[2]client.Payment{{To: bobAddr, Value: toBob}, {To: change, Value: total - toBob}})
	if err != nil {
		return err
	}
	if err := prove(transferProver, transferDir, "", tr.Circuit); err != nil {
		return err
	}
	st := tr.Statement
	file.Transfer = poolTransfer{
		Root:       note.Hex32(&st.Root),
		Inputs:     []uint64{spends[0].Index, spends[1].Index},
		Recipients: []string{"bob", "alice"},
		AuditBlob:  hexBytes(st.AuditBlob),
		AuditHash:  note.Hex32(&st.AuditHash),
		EncHash:    note.Hex32(&st.EncHash),
		SigHash:    note.Hex32(&st.SigHash),
	}
	for i := range st.Nullifiers {
		file.Transfer.Nullifiers = append(file.Transfer.Nullifiers, note.Hex32(&st.Nullifiers[i]))
		ledger.Spend(st.Nullifiers[i])
	}
	for i := range st.Commitments {
		file.Transfer.Commitments = append(file.Transfer.Commitments, note.Hex32(&st.Commitments[i]))
		file.Transfer.Outputs = append(file.Transfer.Outputs, tr.Outputs[i].ToOpening())
		file.Transfer.EncBlobs = append(file.Transfer.EncBlobs, hexBytes(tr.EncBlobs[i]))
		ledger.Append(st.Commitments[i], tr.EncBlobs[i])
	}

	// Burns against the final tree: Alice unshields note 2, the custodian
	// forfeits note 4 (read from the audit ciphertext, with Alice's
	// registered fvk), Bob unshields what he received.
	root := ledger.Root()
	for _, cm := range ledger.Leaves {
		file.Leaves = append(file.Leaves, note.Hex32(&cm))
	}
	file.Root = note.Hex32(&root)
	alices := alice.Scan(&ledger)
	bobs := bob.Scan(&ledger)
	if len(alices) != int(*count)-2+1 || len(bobs) != 1 {
		return fmt.Errorf("after the transfer alice sees %d notes and bob %d", len(alices), len(bobs))
	}
	auditEPK, auditCTs, err := encrypt.ParseAuditBlob(mustHexBytes(file.Mints[4].AuditBlob))
	if err != nil {
		return err
	}
	seized, err := custodian.AuditDecrypt(&auditEPK, auditCTs)
	if err != nil {
		return err
	}
	type burnSpec struct {
		name, owner string
		circuit     func() (*burn.Circuit, error)
		fvk         note.FullViewingKey
		note        note.Note
		index       uint64
		forced      bool
	}
	specs := []burnSpec{
		{"unshield", "alice", func() (*burn.Circuit, error) {
			return alice.Unshield(&ledger, fixturePool, fixtureDestination, alices[0])
		},
			alice.FullViewingKey(), alices[0].Note, alices[0].Index, false},
		{"forfeit", "alice", func() (*burn.Circuit, error) {
			return client.Forfeit(&ledger, fixturePool, fixtureDestination, seized[0], 4, alice.FullViewingKey())
		}, alice.FullViewingKey(), seized[0], 4, true},
		{"unshield-bob", "bob", func() (*burn.Circuit, error) { return bob.Unshield(&ledger, fixturePool, fixtureDestination, bobs[0]) },
			bob.FullViewingKey(), bobs[0].Note, bobs[0].Index, false},
	}
	for _, b := range specs {
		c, err := b.circuit()
		if err != nil {
			return err
		}
		if err := prove(burnProver, burnDir, b.name, c); err != nil {
			return err
		}
		nf := note.Nullifier(b.fvk.NK, b.note.Commitment(), b.index)
		sh := burn.SigHash(fixturePool, fixtureDestination, nf, b.note.Value)
		path, err := ledger.Path(b.index)
		if err != nil {
			return err
		}
		pb := poolBurn{
			Name: b.name, Owner: b.owner, Index: b.index, Nullifier: note.Hex32(&nf), Forced: b.forced,
			NK: note.Hex32(&b.fvk.NK), Destination: note.HexBytes32(&fixtureDestination), SigHash: note.Hex32(&sh),
		}
		for h := range path.Siblings {
			pb.Siblings = append(pb.Siblings, note.Hex32(&path.Siblings[h]))
		}
		file.Burns = append(file.Burns, pb)
	}

	if err := writeJSON(filepath.Join(*out, "pool.json"), file); err != nil {
		return err
	}
	fmt.Printf("root %s\n", file.Root)
	return nil
}

// prove proves assignment with p and writes proof[-tag].bin and
// public[-tag].bin under dir.
func prove(p *client.Prover, dir, tag string, assignment frontend.Circuit) error {
	proof, public, err := p.Prove(assignment)
	if err != nil {
		return err
	}
	suffix := ""
	if tag != "" {
		suffix = "-" + tag
	}
	sizes, err := export.WriteProof(dir, "proof"+suffix+".bin", "public"+suffix+".bin", proof, public)
	if err != nil {
		return err
	}
	report(dir, sizes)
	return nil
}

// proveAndWrite runs a development setup, proves assignment, self-verifies
// and writes vk.bin, proof.bin and public.bin.
func proveAndWrite(name string, ccs constraint.ConstraintSystem, assignment frontend.Circuit, out string) error {
	fmt.Printf("%s: %d constraints, %d public inputs\n", name, ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)
	p, err := client.NewProver(name, func() (constraint.ConstraintSystem, error) { return ccs, nil })
	if err != nil {
		return err
	}
	var proof groth16.Proof
	var public witness.Witness
	if proof, public, err = p.Prove(assignment); err != nil {
		return err
	}
	sizes, err := export.Write(out, export.Artifacts{VK: p.VK, Proof: proof, Public: public})
	if err != nil {
		return err
	}
	report(out, sizes)
	return nil
}

func report(dir string, sizes map[string]int) {
	names := make([]string, 0, len(sizes))
	for n := range sizes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(dir, n), sizes[n])
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
	return nil
}

func hexBytes(b []byte) string { return "0x" + fmt.Sprintf("%x", b) }

func mustHexBytes(s string) []byte {
	var out []byte
	if _, err := fmt.Sscanf(s, "0x%x", &out); err != nil {
		panic(err)
	}
	return out
}

func ptr(e fr.Element) *fr.Element { return &e }
