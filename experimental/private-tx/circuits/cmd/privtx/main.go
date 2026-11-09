// privtx builds circuits, keys and proofs for the private-tx protocol.
//
//	privtx smoke-fixture   [-out DIR]
//	privtx mint-fixture    [-out DIR] [-value N] [-seed STRING]
//	privtx burn-fixture    [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]
//
// Each fixture subcommand compiles its circuit(s), runs a (development) Groth16
// setup, proves fixed witnesses, self-verifies, and writes vk.bin,
// proof*.bin and public*.bin in gnark's native encodings into DIR for the
// Rust e2e tests, plus a JSON file describing the witnesses so the e2e crate
// can recompute every hash with its own Poseidon.
//
// smoke-fixture proves 3·5 = 15. mint-fixture proves one shield.
// burn-fixture fills a tree with N notes and burns one. Witnesses are
// built through the client package.
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
