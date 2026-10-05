// privtx builds circuits, keys and proofs for the private-tx protocol.
//
//	privtx smoke-fixture [-out DIR]
//	privtx mint-fixture  [-out DIR] [-value N] [-seed STRING]
//
// Each subcommand compiles its circuit, runs a (development) Groth16 setup,
// proves a fixed witness, self-verifies, and writes vk.bin, proof.bin and
// public.bin in gnark's native encodings into DIR for the Rust e2e tests.
// smoke-fixture proves 3·5 = 15; mint-fixture proves a deterministic note
// derived from -seed and also writes note.json (the opening).
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

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/export"
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
	opening, err := json.MarshalIndent(n.ToOpening(), "", "  ")
	if err != nil {
		return err
	}
	opening = append(opening, '\n')
	path := filepath.Join(*out, "note.json")
	if err := os.WriteFile(path, opening, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(opening))
	fmt.Printf("commitment %s\n", n.ToOpening().Commitment)
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
