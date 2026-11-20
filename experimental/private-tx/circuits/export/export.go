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
	sizes, err := WriteVK(dir, "vk.bin", a.VK)
	if err != nil {
		return nil, err
	}
	more, err := WriteProof(dir, "proof.bin", "public.bin", a.Proof, a.Public)
	if err != nil {
		return nil, err
	}
	for k, v := range more {
		sizes[k] = v
	}
	return sizes, nil
}

// WriteVK stores a verifying key under dir/name, creating dir.
func WriteVK(dir, name string, vk groth16.VerifyingKey) (map[string]int, error) {
	w := writer{dir: dir, sizes: map[string]int{}}
	if err := w.mkdir(); err != nil {
		return nil, err
	}
	if err := w.write(name, func(w io.Writer) error { _, err := vk.WriteTo(w); return err }); err != nil {
		return nil, err
	}
	return w.sizes, nil
}

// WriteProof stores a proof and its public witness under dir, creating dir.
// Several proofs for one key share a directory by using distinct names.
func WriteProof(dir, proofName, publicName string, proof groth16.Proof, public witness.Witness) (map[string]int, error) {
	w := writer{dir: dir, sizes: map[string]int{}}
	if err := w.mkdir(); err != nil {
		return nil, err
	}
	if err := w.write(proofName, func(w io.Writer) error { _, err := proof.WriteTo(w); return err }); err != nil {
		return nil, err
	}
	if err := w.write(publicName, func(w io.Writer) error {
		data, err := public.MarshalBinary()
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}); err != nil {
		return nil, err
	}
	return w.sizes, nil
}

type writer struct {
	dir   string
	sizes map[string]int
}

func (w *writer) mkdir() error { return os.MkdirAll(w.dir, 0o755) }

func (w *writer) write(name string, f func(w io.Writer) error) error {
	var buf bytes.Buffer
	if err := f(&buf); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, name), buf.Bytes(), 0o644); err != nil {
		return err
	}
	w.sizes[name] = buf.Len()
	return nil
}
