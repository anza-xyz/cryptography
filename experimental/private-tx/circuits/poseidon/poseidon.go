// Package poseidon adapts third-party circom-compatible Poseidon
// implementations to the field types used by the circuits.
//
// Both the native hash and the gadget are the Poseidon of circomlib over the
// BN254 scalar field (x^5 S-box, 8 full rounds, width-dependent partial
// rounds, zero capacity element, digest = state[0]). These are also the
// parameters of light-poseidon, Solana's sol_poseidon syscall and
// syscall/solana-bn254 in this repository, so an on-chain program can
// recompute any in-circuit hash with one syscall. The tests pin this: known
// answers from circomlib, and gadget equals native on random inputs.
//
//   - native:  github.com/iden3/go-iden3-crypto/poseidon, the reference
//     implementation by circom's authors.
//   - gadget:  github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon.
package poseidon

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	iden3 "github.com/iden3/go-iden3-crypto/poseidon"
	vocdoni "github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon"
)

// MaxInputs is the largest number of inputs a single permutation absorbs.
const MaxInputs = 16

// Hash is the native Poseidon of 1..MaxInputs field elements.
func Hash(inputs ...fr.Element) (fr.Element, error) {
	in := make([]*big.Int, len(inputs))
	for i := range inputs {
		in[i] = inputs[i].BigInt(new(big.Int))
	}
	out, err := iden3.Hash(in)
	if err != nil {
		return fr.Element{}, err
	}
	var e fr.Element
	e.SetBigInt(out)
	return e, nil
}

// MustHash is Hash for input counts known to be supported.
func MustHash(inputs ...fr.Element) fr.Element {
	h, err := Hash(inputs...)
	if err != nil {
		panic(err)
	}
	return h
}

// HashGadget constrains and returns the Poseidon digest of 1..MaxInputs
// circuit variables.
func HashGadget(api frontend.API, inputs ...frontend.Variable) (frontend.Variable, error) {
	return vocdoni.Hash(api, inputs...)
}
