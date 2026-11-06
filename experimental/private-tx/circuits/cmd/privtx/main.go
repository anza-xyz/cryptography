// privtx builds circuits, keys and proofs for the private-tx protocol.
//
//	privtx smoke-fixture   [-out DIR]
//	privtx mint-fixture    [-out DIR] [-value N] [-seed STRING]
//	privtx burn-fixture    [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]
//
// Each subcommand compiles its circuit, runs a (development) Groth16 setup,
// proves a fixed witness, self-verifies, and writes vk.bin, proof.bin and
// public.bin in gnark's native encodings into DIR for the Rust e2e tests.
// smoke-fixture proves 3·5 = 15; mint-fixture proves a deterministic note
// derived from -seed and also writes note.json (the opening);
// burn-fixture fills a tree with N deterministic notes, burns the one at
// index I (as its owner, or as the custodian with -forced), and also writes
// burn.json (the leaves, the opening, root, nullifier and flag) so the e2e
// crate can recompute the tree.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
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
	n := note.FromSeed([]byte(*seed), *value)
	if err := proveAndWrite("C_mint", ccs, mint.Assignment(&n), *out); err != nil {
		return err
	}
	opening := n.ToOpening()
	data, err := json.MarshalIndent(opening, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(*out, "note.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
	fmt.Printf("commitment %s\n", opening.Commitment)
	return nil
}

// burnFixtureFile is burn.json: enough for the e2e crate to rebuild the tree
// and the nullifier with its own Poseidon.
type burnFixtureFile struct {
	Depth     int          `json:"depth"`
	Leaves    []string     `json:"leaves"`
	Index     uint64       `json:"index"`
	Note      note.Opening `json:"note"`
	Root      string       `json:"root"`
	Nullifier string       `json:"nullifier"`
	Forced    bool         `json:"forced"`
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
	n := notes[*index]
	witness := burn.Unshield(&n, &path, note.SpendingKeyFromSeed(seeds[*index]))
	if *forced {
		witness = burn.Forfeit(&n, &path)
	}
	if err := proveAndWrite("C_burn", ccs, witness, *out); err != nil {
		return err
	}
	root, nf := tr.Root(), n.Nullifier()
	file.Note, file.Root, file.Nullifier = n.ToOpening(), note.Hex32(&root), note.Hex32(&nf)
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	p := filepath.Join(*out, "burn.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", p, len(data))
	fmt.Printf("root %s\nnullifier %s\nforced %v\n", file.Root, file.Nullifier, *forced)
	return nil
}

// proveAndWrite runs a development setup, proves assignment, self-verifies
// and writes the artifacts. A real deployment needs an MPC ceremony.
func proveAndWrite(name string, ccs constraint.ConstraintSystem, assignment frontend.Circuit, out string) error {
	fmt.Printf("%s: %d constraints, %d public inputs\n", name, ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	public, err := full.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	sizes, err := export.Write(out, export.Artifacts{VK: vk, Proof: proof, Public: public})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(sizes))
	for n := range sizes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(out, n), sizes[n])
	}
	return nil
}
