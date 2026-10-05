package mint

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

func mustHash(in ...fr.Element) fr.Element { return poseidon.MustHash(in...) }
