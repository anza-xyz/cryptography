package poseidon

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func mustElem(t *testing.T, s string) fr.Element {
	t.Helper()
	var e fr.Element
	if _, err := e.SetString(s); err != nil {
		t.Fatal(err)
	}
	return e
}

// Known answers from circomlibjs (`poseidon([1])`, `poseidon([1,2])`, ...),
// also asserted by light-poseidon's and solana-bn254's test suites. These pin
// the libraries to the parameters of the Solana sol_poseidon syscall.
var knownAnswers = []struct {
	inputs []string
	want   string
}{
	{[]string{"1"}, "0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133"},
	{[]string{"1", "2"}, "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"},
	{[]string{"1", "2", "3"}, "0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732"},
	{[]string{"1", "2", "3", "4"}, "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"},
}

type hashCircuit struct {
	In  []frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *hashCircuit) Define(api frontend.API) error {
	h, err := HashGadget(api, c.In...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.Out)
	return nil
}

func TestNativeKnownAnswers(t *testing.T) {
	for _, kat := range knownAnswers {
		inputs := make([]fr.Element, len(kat.inputs))
		for i, s := range kat.inputs {
			inputs[i] = mustElem(t, s)
		}
		got, err := Hash(inputs...)
		if err != nil {
			t.Fatal(err)
		}
		if want := mustElem(t, kat.want); !got.Equal(&want) {
			t.Errorf("poseidon(%v) = %s, want %s", kat.inputs, got.String(), want.String())
		}
	}
}

func TestGadgetKnownAnswers(t *testing.T) {
	for _, kat := range knownAnswers {
		n := len(kat.inputs)
		valid := &hashCircuit{In: make([]frontend.Variable, n), Out: mustElem(t, kat.want)}
		for i, s := range kat.inputs {
			valid.In[i] = mustElem(t, s)
		}
		if err := test.IsSolved(&hashCircuit{In: make([]frontend.Variable, n)}, valid, ecc.BN254.ScalarField()); err != nil {
			t.Errorf("gadget poseidon(%v): %v", kat.inputs, err)
		}
	}
}

func randomInputs(t *testing.T, n int) []fr.Element {
	t.Helper()
	out := make([]fr.Element, n)
	for i := range out {
		if _, err := out[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Gadget and native agree on random inputs for every width the circuits use,
// and the gadget rejects a wrong digest.
func TestGadgetMatchesNative(t *testing.T) {
	for n := 1; n <= 5; n++ {
		t.Run(fmt.Sprintf("inputs=%d", n), func(t *testing.T) {
			inputs := randomInputs(t, n)
			want := MustHash(inputs...)
			var wrong fr.Element
			wrong.Add(&want, new(fr.Element).SetOne())

			circuit := &hashCircuit{In: make([]frontend.Variable, n)}
			valid := &hashCircuit{In: make([]frontend.Variable, n), Out: want}
			invalid := &hashCircuit{In: make([]frontend.Variable, n), Out: wrong}
			for i := range inputs {
				valid.In[i] = inputs[i]
				invalid.In[i] = inputs[i]
			}
			if err := test.IsSolved(circuit, valid, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid assignment not solved: %v", err)
			}
			if err := test.IsSolved(circuit, invalid, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("wrong digest accepted")
			}
		})
	}
}

func TestUnsupportedWidths(t *testing.T) {
	if _, err := Hash(); err == nil {
		t.Error("zero inputs accepted")
	}
	if _, err := Hash(make([]fr.Element, MaxInputs+1)...); err == nil {
		t.Error("MaxInputs+1 inputs accepted")
	}
}
