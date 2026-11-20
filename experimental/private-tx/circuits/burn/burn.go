// Package burn is C_burn: removal of one note from the pool with a public
// amount, either by its owner (unshield) or by the custodian (forfeiture).
//
// Both are the same relation: the note is in the commitment tree, its
// nullifier is published so it cannot be spent again, and its amount is
// published so the pool program can release the backing (vault withdrawal,
// supply decrease). They differ only in who authorizes:
//
//   - forced = 0, unshield: the witness carries the owner's spend
//     authorization, an EdDSA signature by ask over sighash, and the circuit
//     verifies it against ak. This is Zcash's spend authorization signature
//     with the verification moved into the proof: Solana has no syscall for
//     the embedded curve, so checking it on-chain would cost far more than
//     the proof itself, while in-circuit it costs a few thousand constraints
//     and never reveals ak or a re-randomization of it. The prover needs
//     the full viewing key and the signature, not ask, so proving and
//     signing can live on different machines, as in Zcash.
//   - forced = 1, forfeiture: no signature check. The custodian, who holds
//     the owner's registered full viewing key (ak, nk) and learns the
//     opening from the audit ciphertext, removes the note without ask. The
//     program must require the custodian's signature when this flag is set;
//     the circuit only tells it which case it is in.
//
// In both cases the witness proves the note belongs to the key: ivk =
// Poseidon(IVK, ak, nk) and pk_d = [ivk]g_d, with g_d not of small order.
// That is what ties nk, and so the published nullifier, to this note: a
// forfeiture with a made-up nk would publish a nullifier that leaves the
// real one unspent, and the note could be spent again after its value had
// been released.
//
// sighash is the message the owner signs, Zcash's SIGHASH for this one
// spend: it binds the transaction's destination and pool to the proof, so a
// proof fished out of the mempool cannot be replayed with another recipient.
// The program recomputes it from the instruction and passes it as a public
// input (see SigHash).
//
// Public inputs, in order:
//
//	0  root        a commitment tree root the program accepts
//	1  nullifier   Poseidon(NF, nk, cm, leaf index), see package note
//	2  value       the note amount
//	3  forced      0 or 1
//	4  sighash     Poseidon(SIGHASH, pool, destination, nullifier, value), see SigHash
//
// Private witness: ak, nk, g_d, pk_d, r, the signature (R, S; ignored when
// forced), leaf index, Merkle siblings.
//
// The value needs no range check here: it is bound to a leaf of the tree,
// and every leaf was range-checked by the circuit that created it.
package burn

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/domain"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Circuit is the burn relation. Field order fixes the public input order.
type Circuit struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Value     frontend.Variable `gnark:",public"`
	Forced    frontend.Variable `gnark:",public"`
	SigHash   frontend.Variable `gnark:",public"`

	AK        eddsa.PublicKey
	NK        frontend.Variable
	GD        twistededwards.Point
	PKD       twistededwards.Point
	R         frontend.Variable
	Signature eddsa.Signature
	Path      merkle.PathVars
}

// Define constrains forced ∈ {0, 1}; ivk = Poseidon(IVK, ak, nk);
// g_d not of small order; pk_d = [ivk]g_d;
// forced ∨ EdDSA.Verify(ak, sighash, signature);
// root = MerkleRoot(cm, path) with cm = Poseidon(CM, value, g_d, pk_d, r);
// nullifier = Poseidon(NF, nk, cm, index).
func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Forced)

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	// The note belongs to (ak, nk).
	ivk, err := note.IVKGadget(api, c.AK, c.NK)
	if err != nil {
		return err
	}
	note.AssertNotSmallOrder(curve, c.GD)
	// Plain double-and-add over the scalar's bits (DoubleBaseScalarMul
	// without WithIncompleteArithmetic), complete for any point and scalar.
	// gnark's ScalarMul takes the faster lattice path, whose range checks
	// are commitment-based under Groth16, which the on-chain verifier
	// rejects (see "Circuit rules" in README.md).
	pkd := curve.DoubleBaseScalarMul(c.GD, c.GD, ivk, 0)
	api.AssertIsEqual(pkd.X, c.PKD.X)
	api.AssertIsEqual(pkd.Y, c.PKD.Y)

	// The owner consents, unless forced.
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	ok, err := eddsa.IsValid(curve, c.Signature, c.SigHash, c.AK, &h)
	if err != nil {
		return err
	}
	// (1 - forced) · (1 - ok) = 0: a valid signature unless forced.
	api.AssertIsEqual(api.Mul(api.Sub(1, c.Forced), api.Sub(1, ok)), 0)

	// The note is in the tree, and this is its nullifier.
	cm, err := note.CommitmentGadget(api, c.Value, c.GD, c.PKD, c.R)
	if err != nil {
		return err
	}
	root, err := merkle.RootGadget(api, cm, c.Path)
	if err != nil {
		return err
	}
	api.AssertIsEqual(root, c.Root)

	nf, err := note.NullifierGadget(api, c.NK, cm, c.Path.Index)
	if err != nil {
		return err
	}
	api.AssertIsEqual(nf, c.Nullifier)
	return nil
}

// SigHash is the message a burn's owner signs and the program recomputes:
//
//	Poseidon(SIGHASH, pool[0:16], pool[16:32], destination[0:16], destination[16:32], nullifier, value)
//
// Solana addresses are 256 bits and do not fit one field element, so each is
// split into two 128-bit big-endian halves. The nullifier identifies the
// note; the value is what the destination receives. Root and forced are
// already public inputs of the same proof, so the hash need not repeat them.
func SigHash(pool, destination [32]byte, nullifier fr.Element, value uint64) fr.Element {
	var v fr.Element
	v.SetUint64(value)
	return poseidon.MustHash(domain.Tag(domain.SIGHASH), half(pool, 0), half(pool, 16), half(destination, 0), half(destination, 16), nullifier, v)
}

func half(b [32]byte, from int) fr.Element {
	var e fr.Element
	e.SetBytes(b[from : from+16])
	return e
}

// Unshield builds the owner's witness for burning n, which sits in the tree
// at path, to destination, with spending key k.
func Unshield(n *note.Note, path *merkle.Path, k note.SpendingKey, pool, destination [32]byte) (*Circuit, error) {
	c := assignment(n, path, k.FullViewingKey(), pool, destination)
	sig, err := k.Sign(c.SigHash.(fr.Element))
	if err != nil {
		return nil, err
	}
	c.Forced = 0
	c.Signature = sig.Vars()
	return c, nil
}

// Forfeit builds the custodian's witness for burning n with the owner's
// full viewing key but not their spending key.
func Forfeit(n *note.Note, path *merkle.Path, fvk note.FullViewingKey, pool, destination [32]byte) *Circuit {
	c := assignment(n, path, fvk, pool, destination)
	c.Forced = 1
	d := note.Dummy()
	c.Signature = d.Vars()
	return c
}

func assignment(n *note.Note, path *merkle.Path, fvk note.FullViewingKey, pool, destination [32]byte) *Circuit {
	cm := n.Commitment()
	nf := note.Nullifier(fvk.NK, cm, path.Index)
	gd := n.GD()
	return &Circuit{
		Root:      path.Root(cm),
		Nullifier: nf,
		Value:     n.Value,
		SigHash:   SigHash(pool, destination, nf, n.Value),
		AK:        note.AKVars(&fvk.AK),
		NK:        fvk.NK,
		GD:        note.PointVars(&gd),
		PKD:       note.PointVars(&n.PKD),
		R:         n.R,
		Path:      path.Vars(),
	}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
