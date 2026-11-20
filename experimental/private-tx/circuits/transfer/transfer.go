// Package transfer is C_transfer: an in-pool shielded transfer of fixed
// arity, two notes in and two out.
//
// Each input is C_burn's spend relation: the note belongs to the key
// (ivk = Poseidon(IVK, ak, nk), pk_d = [ivk]g_d), sits in the tree under
// the published root, has the published nullifier, and its owner signed
// the sighash. A zero-value input is a dummy, as in Sapling: its root
// check is skipped (the note is not in the tree), but it still needs a
// well-formed owner, nullifier and signature, so every transaction has
// the same shape whatever it spends.
//
// Each output is C_mint's note relation: a well-formed address with
// g_d = GroupHash(d), a 64-bit value, the published commitment. Values are conserved exactly; there is
// no fee or public value in this circuit.
//
// The outputs are encrypted to the custodian inside the circuit (package
// encrypt), and audit_hash commits to that ciphertext; the recipient
// ciphertexts are not constrained but are bound through enc_hash in the
// sighash, so a transaction cannot be altered in flight.
//
// Public inputs, in order:
//
//	0  root
//	1  nullifier_0
//	2  nullifier_1
//	3  commitment_0
//	4  commitment_1
//	5  audit_hash   Poseidon(AUDIT, apk, epk, c_0..c_5)
//	6  sighash      Poseidon(TSIGHASH, pool, nf_0, nf_1, cm_0, cm_1, audit_hash, enc_hash)
//
// The program recomputes audit_hash from the audit blob and its audit
// key, enc_hash from the recipient blobs, and sighash from both and the
// other public inputs. Both input owners sign the same sighash.
package transfer

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/domain"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Arity of the transaction.
const (
	NumInputs  = 2
	NumOutputs = 2
)

// InputVars is one spent note as circuit variables.
type InputVars struct {
	AK        eddsa.PublicKey
	NK        frontend.Variable
	GD        gadgetted.Point
	PKD       gadgetted.Point
	R         frontend.Variable
	Value     frontend.Variable
	Path      merkle.PathVars
	Signature eddsa.Signature
}

// Circuit is the transfer relation. Field order fixes the public input order.
type Circuit struct {
	Root        frontend.Variable `gnark:",public"`
	Nullifier0  frontend.Variable `gnark:",public"`
	Nullifier1  frontend.Variable `gnark:",public"`
	Commitment0 frontend.Variable `gnark:",public"`
	Commitment1 frontend.Variable `gnark:",public"`
	AuditHash   frontend.Variable `gnark:",public"`
	SigHash     frontend.Variable `gnark:",public"`

	Inputs   [NumInputs]InputVars
	Outputs  [NumOutputs]encrypt.OutputVars
	GDProofs [NumOutputs]note.GroupHashVars
	AuditPK  gadgetted.Point
	ESK      frontend.Variable
}

// Define constrains the relation described in the package comment.
func (c *Circuit) Define(api frontend.API) error {
	curve, err := gadgetted.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	nullifiers := [NumInputs]frontend.Variable{c.Nullifier0, c.Nullifier1}
	commitments := [NumOutputs]frontend.Variable{c.Commitment0, c.Commitment1}

	var sumIn, sumOut frontend.Variable = 0, 0
	for i, in := range c.Inputs {
		// The note belongs to (ak, nk).
		ivk, err := note.IVKGadget(api, in.AK, in.NK)
		if err != nil {
			return err
		}
		note.AssertNotSmallOrder(curve, in.GD)
		pkd := curve.DoubleBaseScalarMul(in.GD, in.GD, ivk, 0)
		api.AssertIsEqual(pkd.X, in.PKD.X)
		api.AssertIsEqual(pkd.Y, in.PKD.Y)

		// It is in the tree, unless it is a dummy.
		cm, err := note.CommitmentGadget(api, in.Value, in.GD, in.PKD, in.R)
		if err != nil {
			return err
		}
		root, err := merkle.RootGadget(api, cm, in.Path)
		if err != nil {
			return err
		}
		isDummy := api.IsZero(in.Value)
		api.AssertIsEqual(api.Mul(api.Sub(root, c.Root), api.Sub(1, isDummy)), 0)

		// This is its nullifier.
		nf, err := note.NullifierGadget(api, in.NK, cm, in.Path.Index)
		if err != nil {
			return err
		}
		api.AssertIsEqual(nf, nullifiers[i])

		// Its owner consents to this transaction.
		h, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		if err := eddsa.Verify(curve, in.Signature, c.SigHash, in.AK, &h); err != nil {
			return err
		}
		sumIn = api.Add(sumIn, in.Value)
	}

	for i, out := range c.Outputs {
		api.ToBinary(out.Value, 64)
		api.ToBinary(out.D, note.DiversifierSize*8)
		if err := note.GroupHashGadget(api, curve, out.D, c.GDProofs[i], out.GD); err != nil {
			return err
		}
		note.AssertNotSmallOrder(curve, out.GD)
		curve.AssertIsOnCurve(out.PKD)
		cm, err := note.CommitmentGadget(api, out.Value, out.GD, out.PKD, out.R)
		if err != nil {
			return err
		}
		api.AssertIsEqual(cm, commitments[i])
		sumOut = api.Add(sumOut, out.Value)
	}
	api.AssertIsEqual(sumIn, sumOut)

	auditHash, err := encrypt.AuditGadget(api, curve, c.AuditPK, c.ESK, c.Outputs[:])
	if err != nil {
		return err
	}
	api.AssertIsEqual(auditHash, c.AuditHash)
	return nil
}

// SigHash is the message both owners sign and the program recomputes:
// Poseidon(TSIGHASH, pool halves, nf_0, nf_1, cm_0, cm_1, audit_hash, enc_hash).
func SigHash(pool [32]byte, nullifiers, commitments [2]fr.Element, auditHash, encHash fr.Element) fr.Element {
	var hi, lo fr.Element
	hi.SetBytes(pool[:16])
	lo.SetBytes(pool[16:])
	return poseidon.MustHash(domain.Tag(domain.TSIGHASH), hi, lo,
		nullifiers[0], nullifiers[1], commitments[0], commitments[1], auditHash, encHash)
}

// Spend is one input: the note, where it sits, and the key that owns it.
type Spend struct {
	Note note.Note
	Path merkle.Path
	Key  note.SpendingKey
}

// Dummy is a zero-value spend of a fresh note under key, not in any tree.
func Dummy(rng io.Reader, key note.SpendingKey) (Spend, error) {
	fvk := key.FullViewingKey()
	var d note.Diversifier
	if _, err := io.ReadFull(rng, d[:]); err != nil {
		return Spend{}, err
	}
	addr, err := fvk.Address(d)
	if err != nil {
		return Spend{}, err
	}
	n, err := note.Random(rng, 0, addr)
	if err != nil {
		return Spend{}, err
	}
	return Spend{Note: n, Path: merkle.EmptyPath(), Key: key}, nil
}

// Params is everything a transfer is built from.
type Params struct {
	Pool    [32]byte
	Root    fr.Element // the root the real spends are proved against
	Spends  [NumInputs]Spend
	Outputs [NumOutputs]note.Note
	AuditPK twistededwards.PointAffine
	ESK     fr.Element
	// EncBlobs are the recipient blobs of the outputs, in order.
	EncBlobs [NumOutputs][]byte
}

// Statement is what the transaction carries besides the proof.
type Statement struct {
	Root        fr.Element
	Nullifiers  [NumInputs]fr.Element
	Commitments [NumOutputs]fr.Element
	AuditHash   fr.Element
	EncHash     fr.Element
	SigHash     fr.Element
	AuditBlob   []byte
}

// Build computes the statement, signs it with both spend keys and returns
// the full witness.
func Build(p *Params) (*Circuit, *Statement, error) {
	var st Statement
	st.Root = p.Root
	for i, sp := range p.Spends {
		if sp.Note.Value != 0 {
			if got := sp.Path.Root(sp.Note.Commitment()); !got.Equal(&p.Root) {
				return nil, nil, fmt.Errorf("transfer: spend %d is not under the root", i)
			}
		}
		st.Nullifiers[i] = note.Nullifier(sp.Key.FullViewingKey().NK, sp.Note.Commitment(), sp.Path.Index)
	}
	var sumIn, sumOut uint64
	for _, sp := range p.Spends {
		sumIn += sp.Note.Value
	}
	outs := make([]*note.Note, NumOutputs)
	for i := range p.Outputs {
		outs[i] = &p.Outputs[i]
		st.Commitments[i] = p.Outputs[i].Commitment()
		sumOut += p.Outputs[i].Value
	}
	if sumIn != sumOut {
		return nil, nil, fmt.Errorf("transfer: inputs %d != outputs %d", sumIn, sumOut)
	}
	epk, cts := encrypt.AuditEncrypt(p.ESK, &p.AuditPK, outs...)
	st.AuditHash = encrypt.AuditHash(&p.AuditPK, &epk, cts)
	st.AuditBlob = encrypt.AuditBlob(&epk, cts)
	st.EncHash = encrypt.EncHash(p.EncBlobs[0], p.EncBlobs[1])
	st.SigHash = SigHash(p.Pool, st.Nullifiers, st.Commitments, st.AuditHash, st.EncHash)

	c := &Circuit{
		Root:        st.Root,
		Nullifier0:  st.Nullifiers[0],
		Nullifier1:  st.Nullifiers[1],
		Commitment0: st.Commitments[0],
		Commitment1: st.Commitments[1],
		AuditHash:   st.AuditHash,
		SigHash:     st.SigHash,
		AuditPK:     note.PointVars(&p.AuditPK),
		ESK:         p.ESK,
	}
	for i, sp := range p.Spends {
		fvk := sp.Key.FullViewingKey()
		gd := sp.Note.GD()
		sig, err := sp.Key.Sign(st.SigHash)
		if err != nil {
			return nil, nil, err
		}
		c.Inputs[i] = InputVars{
			AK:        note.AKVars(&fvk.AK),
			NK:        fvk.NK,
			GD:        note.PointVars(&gd),
			PKD:       note.PointVars(&sp.Note.PKD),
			R:         sp.Note.R,
			Value:     sp.Note.Value,
			Path:      sp.Path.Vars(),
			Signature: sig.Vars(),
		}
	}
	for i := range p.Outputs {
		c.Outputs[i] = OutputVars(&p.Outputs[i])
		gdw, err := p.Outputs[i].D.GroupHashWitness()
		if err != nil {
			return nil, nil, err
		}
		c.GDProofs[i] = gdw.Vars()
	}
	return c, &st, nil
}

// OutputVars converts an output note to the audit gadget's form.
func OutputVars(n *note.Note) encrypt.OutputVars {
	gd := n.GD()
	return encrypt.OutputVars{
		GD:    note.PointVars(&gd),
		PKD:   note.PointVars(&n.PKD),
		R:     n.R,
		Value: n.Value,
		D:     n.D.Element(),
	}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
