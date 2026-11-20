// Package mint is C_mint: issuance of one note into a pool with a public
// amount.
//
// The issuing institution creates a note for a recipient and publishes the
// amount and the note commitment. The proof shows the commitment opens to a
// well-formed note carrying exactly that amount, so the pool program can
// account for the minted value (and, for a wrapped asset, match it against
// the vault deposit) while the recipient stays hidden. Who may mint is
// enforced by the pool program (issuer authority), not in-circuit.
//
// Public inputs, in order:
//
//	0  commitment   Poseidon(value, owner_pk, rho, r)
//	1  value        the note amount, < 2^64
//
// Private witness: owner_pk, rho, r.
package mint

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gadgetted "github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
)

// ValueBits is the width of the note value range check.
const ValueBits = 64

// Circuit is the mint relation. Field order fixes the public input order.
type Circuit struct {
	Commitment frontend.Variable `gnark:",public"`
	Value      frontend.Variable `gnark:",public"`
	AuditHash  frontend.Variable `gnark:",public"`

	GD      gadgetted.Point
	PKD     gadgetted.Point
	R       frontend.Variable
	D       frontend.Variable
	GDProof note.GroupHashVars
	AuditPK gadgetted.Point
	ESK     frontend.Variable
	// EncHash binds the recipient blob: the program recomputes it from the
	// instruction and it enters audit_hash, since a mint has no sighash.
	EncHash frontend.Variable
}

// Define constrains value ∈ [0, 2^64), g_d = GroupHash(d), commitment =
// Poseidon(CM, value, g_d, pk_d, r), and audit_hash over the note's audit
// ciphertext (package encrypt) and the recipient blob's hash.
//
// The value is public, so the on-chain verifier already rejects a non-canonical
// scalar; the bit decomposition still bounds it to 64 bits so every leaf in the
// tree carries a value later conservation checks can add without wrapping. It
// is a plain ToBinary rather than gnark's std/rangecheck: the latter uses a
// commitment-based lookup under Groth16, which adds a commitment key to the
// verifying key and a Pedersen commitment to the proof, and the on-chain
// verifier implements plain Groth16 only.
//
// The address (g_d, pk_d) is checked to be two curve points with g_d not of
// small order, as Sapling's Output does, so no note can be created whose
// owner relation pk_d = [ivk]g_d binds only a few bits of ivk.
func (c *Circuit) Define(api frontend.API) error {
	api.ToBinary(c.Value, ValueBits)
	curve, err := gadgetted.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	api.ToBinary(c.D, note.DiversifierSize*8)
	// g_d = GroupHash(d), so the audit ciphertext's d names the base the
	// commitment was made with and the custodian can always recompute it.
	if err := note.GroupHashGadget(api, curve, c.D, c.GDProof, c.GD); err != nil {
		return err
	}
	note.AssertNotSmallOrder(curve, c.GD)
	curve.AssertIsOnCurve(c.PKD)
	cm, err := note.CommitmentGadget(api, c.Value, c.GD, c.PKD, c.R)
	if err != nil {
		return err
	}
	api.AssertIsEqual(cm, c.Commitment)

	out := encrypt.OutputVars{GD: c.GD, PKD: c.PKD, R: c.R, Value: c.Value, D: c.D}
	auditHash, err := encrypt.AuditGadget(api, curve, c.AuditPK, c.ESK, []encrypt.OutputVars{out}, c.EncHash)
	if err != nil {
		return err
	}
	api.AssertIsEqual(auditHash, c.AuditHash)
	return nil
}

// Statement is what the transaction carries besides the proof.
type Statement struct {
	Commitment fr.Element
	Value      uint64
	AuditHash  fr.Element
	EncHash    fr.Element
	AuditBlob  []byte
}

// Build computes the statement for minting n, encrypted to apk with esk
// and to its recipient as encBlob, and returns the full witness.
func Build(n *note.Note, apk *twistededwards.PointAffine, esk fr.Element, encBlob []byte) (*Circuit, *Statement) {
	epk, cts := encrypt.AuditEncrypt(esk, apk, n)
	st := &Statement{
		Commitment: n.Commitment(),
		Value:      n.Value,
		EncHash:    encrypt.EncHash(encBlob),
		AuditBlob:  encrypt.AuditBlob(&epk, cts),
	}
	st.AuditHash = encrypt.AuditHash(apk, &epk, cts, st.EncHash)
	gdw, err := n.D.GroupHashWitness()
	if err != nil {
		panic(err) // the note's g_d exists, so its witness does
	}
	return &Circuit{
		Commitment: st.Commitment,
		Value:      n.Value,
		AuditHash:  st.AuditHash,
		GD:         note.PointVars(&gdw.GD),
		PKD:        note.PointVars(&n.PKD),
		R:          n.R,
		D:          n.D.Element(),
		GDProof:    gdw.Vars(),
		AuditPK:    note.PointVars(apk),
		ESK:        esk,
		EncHash:    st.EncHash,
	}, st
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
