// Package export writes Groth16 artifacts in gnark's native encodings, which
// the verifier program's groth16-convert tool consumes:
//
//	vk.bin      VerifyingKey.WriteTo         (compressed points)
//	proof.bin   Proof.WriteTo                (compressed points)
//	public.bin  public Witness.MarshalBinary (u32 nbPublic ‖ u32 nbSecret ‖ u32 len ‖ Fr…)
package export

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// Artifacts is one proof with everything needed to verify it.
type Artifacts struct {
	VK     groth16.VerifyingKey
	Proof  groth16.Proof
	Public witness.Witness
}

// Write stores vk.bin, proof.bin and public.bin under dir, creating it.
// It returns the written sizes by file name.
func Write(dir string, a Artifacts) (map[string]int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sizes := map[string]int{}
	write := func(name string, f func(w io.Writer) error) error {
		var buf bytes.Buffer
		if err := f(&buf); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
			return err
		}
		sizes[name] = buf.Len()
		return nil
	}
	if err := write("vk.bin", func(w io.Writer) error { _, err := a.VK.WriteTo(w); return err }); err != nil {
		return nil, err
	}
	if err := write("proof.bin", func(w io.Writer) error { _, err := a.Proof.WriteTo(w); return err }); err != nil {
		return nil, err
	}
	if err := write("public.bin", func(w io.Writer) error {
		data, err := a.Public.MarshalBinary()
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}); err != nil {
		return nil, err
	}
	return sizes, nil
}
