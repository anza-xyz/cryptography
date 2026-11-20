package main

// Wallet-side subcommands for a live cluster: persistent keys and proving
// keys, and the three proofs a demo needs, each written as JSON the Rust
// CLI turns into an instruction. Every address or key crossing the
// Go/Rust boundary is 0x-prefixed hex.
//
//	privtx setup         -keys DIR                      compile + Groth16 setup, write <circuit>.pk/.vk and <circuit>/vk.bin
//	privtx keygen        -out FILE [-seed S]            a spending key
//	privtx audit-keygen  -out FILE [-seed S]            the custodian's audit key
//	privtx address       -wallet FILE [-d HEX]          a payment address of the wallet
//	privtx shield        -keys DIR -to ADDR -value N -audit-pk FILE -out JSON
//	privtx scan          -wallet FILE -ledger JSON      the wallet's unspent notes
//	privtx transfer      -keys DIR -wallet FILE -ledger JSON -pool HEX -audit-pk FILE -spend I[,J] -to ADDR -value N -out JSON
//	privtx unshield      -keys DIR -wallet FILE -ledger JSON -pool HEX -destination HEX -index I -out JSON

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/client"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/encrypt"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/export"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/mint"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/transfer"
)

// circuits are the provable circuits by name.
var circuits = map[string]func() (constraint.ConstraintSystem, error){
	"mint":     mint.Compile,
	"transfer": transfer.Compile,
	"burn":     burn.Compile,
}

func setupCmd(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	keys := fs.String("keys", "keys", "directory for the proving and verifying keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*keys, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"mint", "transfer", "burn"} {
		p, err := client.NewProver(name, circuits[name])
		if err != nil {
			return err
		}
		fmt.Printf("%s: %d constraints, %d public inputs\n", name, p.CCS.GetNbConstraints(), p.CCS.GetNbPublicVariables()-1)
		for ext, w := range map[string]interface {
			WriteTo(io.Writer) (int64, error)
		}{".pk": p.PK, ".vk": p.VK} {
			path := filepath.Join(*keys, name+ext)
			f, err := os.Create(path)
			if err != nil {
				return err
			}
			n, err := w.WriteTo(f)
			f.Close()
			if err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d bytes)\n", path, n)
		}
		// The verifier's input format, for registration on-chain.
		sizes, err := export.WriteVK(filepath.Join(*keys, name), "vk.bin", p.VK)
		if err != nil {
			return err
		}
		report(filepath.Join(*keys, name), sizes)
		// What the keys were made for, so a stale key is caught at load.
		if err := writeJSON(filepath.Join(*keys, name+".json"), keyMeta{Constraints: p.CCS.GetNbConstraints()}); err != nil {
			return err
		}
	}
	return nil
}

// keyMeta pins a key pair to the circuit it was set up for.
type keyMeta struct {
	Constraints int `json:"constraints"`
}

// loadProver reads the keys written by setup and recompiles the circuit,
// refusing keys made for another version of it.
func loadProver(keys, name string) (*client.Prover, error) {
	ccs, err := circuits[name]()
	if err != nil {
		return nil, err
	}
	var meta keyMeta
	if err := readJSON(filepath.Join(keys, name+".json"), &meta); err != nil {
		return nil, fmt.Errorf("%s: %w (run `privtx setup`)", name, err)
	}
	if meta.Constraints != ccs.GetNbConstraints() {
		return nil, fmt.Errorf("%s: keys in %s were set up for %d constraints, the circuit has %d: rerun `privtx setup`", name, keys, meta.Constraints, ccs.GetNbConstraints())
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	for ext, r := range map[string]interface {
		ReadFrom(io.Reader) (int64, error)
	}{".pk": pk, ".vk": vk} {
		f, err := os.Open(filepath.Join(keys, name+ext))
		if err != nil {
			return nil, err
		}
		_, err = r.ReadFrom(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s%s: %w", name, ext, err)
		}
	}
	return &client.Prover{Name: name, CCS: ccs, PK: pk, VK: vk}, nil
}

// walletFile is a spending key on disk.
type walletFile struct {
	SK string `json:"sk"`
}

func keygenCmd(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "wallet file to write")
	seed := fs.String("seed", "", "derive deterministically from this seed instead of randomly")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	var sk fr.Element
	if *seed != "" {
		sk = fixtureScalar(*seed)
	} else if _, err := sk.SetRandom(); err != nil {
		return err
	}
	if err := writeSecretJSON(*out, walletFile{SK: note.Hex32(&sk)}); err != nil {
		return err
	}
	w := client.Wallet{Key: note.NewSpendingKey(sk)}
	fvk := w.FullViewingKey()
	ivk := fvk.IVK()
	fmt.Printf("ak   %s %s\nnk   %s\nivk  %s\n", note.Hex32(&fvk.AK.X), note.Hex32(&fvk.AK.Y), note.Hex32(&fvk.NK), note.Hex32(&ivk))
	return nil
}

func loadWallet(path string) (*client.Wallet, error) {
	var f walletFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	var sk fr.Element
	if err := note.ParseHex32(f.SK, &sk); err != nil {
		return nil, err
	}
	return &client.Wallet{Key: note.NewSpendingKey(sk)}, nil
}

// auditFile is the custodian's audit key on disk.
type auditFile struct {
	SK  string `json:"sk"`
	PKX string `json:"pk_x"`
	PKY string `json:"pk_y"`
}

func auditKeygenCmd(args []string) error {
	fs := flag.NewFlagSet("audit-keygen", flag.ExitOnError)
	out := fs.String("out", "", "audit key file to write")
	seed := fs.String("seed", "", "derive deterministically from this seed instead of randomly")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	var sk fr.Element
	if *seed != "" {
		sk = fixtureScalar(*seed)
	} else if _, err := sk.SetRandom(); err != nil {
		return err
	}
	k := encrypt.NewAuditKey(sk)
	if err := writeSecretJSON(*out, auditFile{SK: note.Hex32(&sk), PKX: note.Hex32(&k.PK.X), PKY: note.Hex32(&k.PK.Y)}); err != nil {
		return err
	}
	fmt.Printf("audit_pk %s %s\n", note.Hex32(&k.PK.X), note.Hex32(&k.PK.Y))
	return nil
}

func loadAuditPK(path string) (twistededwards.PointAffine, error) {
	var f auditFile
	if err := readJSON(path, &f); err != nil {
		return twistededwards.PointAffine{}, err
	}
	var pk twistededwards.PointAffine
	if err := note.ParseHex32(f.PKX, &pk.X); err != nil {
		return pk, err
	}
	if err := note.ParseHex32(f.PKY, &pk.Y); err != nil {
		return pk, err
	}
	if !pk.IsOnCurve() {
		return pk, fmt.Errorf("audit key is not on the curve")
	}
	return pk, nil
}

// Address encoding: d (11 bytes) ‖ pk_d (compressed, 32 bytes), hex.
func encodeAddress(a note.Address) string {
	c := a.PKD.Bytes()
	return "0x" + hex.EncodeToString(append(append([]byte{}, a.D[:]...), c[:]...))
}

func decodeAddress(s string) (note.Address, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != note.DiversifierSize+fr.Bytes {
		return note.Address{}, fmt.Errorf("address: want %d hex bytes", note.DiversifierSize+fr.Bytes)
	}
	var a note.Address
	copy(a.D[:], b[:note.DiversifierSize])
	if _, err := a.PKD.SetBytes(b[note.DiversifierSize:]); err != nil || !a.PKD.IsOnCurve() {
		return note.Address{}, fmt.Errorf("address: bad pk_d")
	}
	return a, nil
}

func addressCmd(args []string) error {
	fs := flag.NewFlagSet("address", flag.ExitOnError)
	wallet := fs.String("wallet", "", "wallet file")
	dHex := fs.String("d", "", "diversifier (11 bytes hex); random if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w, err := loadWallet(*wallet)
	if err != nil {
		return err
	}
	var d note.Diversifier
	if *dHex != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(*dHex, "0x"))
		if err != nil || len(b) != note.DiversifierSize {
			return fmt.Errorf("-d: want %d hex bytes", note.DiversifierSize)
		}
		copy(d[:], b)
	} else if _, err := rand.Read(d[:]); err != nil {
		return err
	}
	a, err := w.Address(d)
	if err != nil {
		return err
	}
	fmt.Println(encodeAddress(a))
	return nil
}

// proofJSON is the common part of every proof the CLI writes: gnark's
// native proof and public witness, hex.
type proofJSON struct {
	Proof  string `json:"proof"`
	Public string `json:"public"`
}

func proofOf(p *client.Prover, assignment frontend.Circuit) (proofJSON, error) {
	proof, public, err := p.Prove(assignment)
	if err != nil {
		return proofJSON{}, err
	}
	var pb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		return proofJSON{}, err
	}
	wb, err := public.MarshalBinary()
	if err != nil {
		return proofJSON{}, err
	}
	return proofJSON{Proof: hexBytes(pb.Bytes()), Public: hexBytes(wb)}, nil
}

type shieldJSON struct {
	proofJSON
	Note       note.Opening `json:"note"`
	Commitment string       `json:"commitment"`
	Value      uint64       `json:"value"`
	AuditHash  string       `json:"audit_hash"`
	AuditBlob  string       `json:"audit_blob"`
	EncBlob    string       `json:"enc_blob"`
}

func shieldCmd(args []string) error {
	fs := flag.NewFlagSet("shield", flag.ExitOnError)
	keys := fs.String("keys", "keys", "keys directory")
	to := fs.String("to", "", "recipient address")
	value := fs.Uint64("value", 0, "amount in base units")
	auditPK := fs.String("audit-pk", "", "audit key file (the public part is used)")
	out := fs.String("out", "shield.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addr, err := decodeAddress(*to)
	if err != nil {
		return err
	}
	apk, err := loadAuditPK(*auditPK)
	if err != nil {
		return err
	}
	p, err := loadProver(*keys, "mint")
	if err != nil {
		return err
	}
	sh, err := client.NewShield(rand.Reader, addr, *value, &apk)
	if err != nil {
		return err
	}
	pj, err := proofOf(p, sh.Circuit)
	if err != nil {
		return err
	}
	st := sh.Statement
	return writeJSON(*out, shieldJSON{
		proofJSON:  pj,
		Note:       sh.Note.ToOpening(),
		Commitment: note.Hex32(&st.Commitment),
		Value:      st.Value,
		AuditHash:  note.Hex32(&st.AuditHash),
		AuditBlob:  hexBytes(st.AuditBlob),
		EncBlob:    hexBytes(sh.EncBlob),
	})
}

// ledgerJSON is what the Rust indexer exports: the pool's leaves, their
// recipient blobs and the nullifiers seen.
type ledgerJSON struct {
	Leaves     []string `json:"leaves"`
	Blobs      []string `json:"blobs"`
	Nullifiers []string `json:"nullifiers"`
}

func loadLedger(path string) (*client.Ledger, error) {
	var f ledgerJSON
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	if len(f.Leaves) != len(f.Blobs) {
		return nil, fmt.Errorf("ledger: %d leaves, %d blobs", len(f.Leaves), len(f.Blobs))
	}
	var l client.Ledger
	for i := range f.Leaves {
		var cm fr.Element
		if err := note.ParseHex32(f.Leaves[i], &cm); err != nil {
			return nil, fmt.Errorf("ledger leaf %d: %w", i, err)
		}
		l.Append(cm, mustHexBytes(f.Blobs[i]))
	}
	for i, s := range f.Nullifiers {
		var nf fr.Element
		if err := note.ParseHex32(s, &nf); err != nil {
			return nil, fmt.Errorf("ledger nullifier %d: %w", i, err)
		}
		l.Spend(nf)
	}
	return &l, nil
}

func scanCmd(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	wallet := fs.String("wallet", "", "wallet file")
	ledger := fs.String("ledger", "ledger.json", "ledger file from the indexer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w, err := loadWallet(*wallet)
	if err != nil {
		return err
	}
	l, err := loadLedger(*ledger)
	if err != nil {
		return err
	}
	owned := w.Scan(l)
	var total uint64
	for _, o := range owned {
		cm := o.Note.Commitment()
		fmt.Printf("index %d  value %d  commitment %s\n", o.Index, o.Note.Value, note.Hex32(&cm))
		total += o.Note.Value
	}
	fmt.Printf("%d notes, %d total\n", len(owned), total)
	return nil
}

func parse32(s string) ([32]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	var out [32]byte
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("want 32 hex bytes, got %q", s)
	}
	copy(out[:], b)
	return out, nil
}

type transferJSON struct {
	proofJSON
	Root        string         `json:"root"`
	Nullifiers  []string       `json:"nullifiers"`
	Commitments []string       `json:"commitments"`
	AuditHash   string         `json:"audit_hash"`
	EncHash     string         `json:"enc_hash"`
	SigHash     string         `json:"sighash"`
	AuditBlob   string         `json:"audit_blob"`
	EncBlobs    []string       `json:"enc_blobs"`
	Outputs     []note.Opening `json:"outputs"`
}

func transferCmd(args []string) error {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	keys := fs.String("keys", "keys", "keys directory")
	wallet := fs.String("wallet", "", "wallet file")
	ledger := fs.String("ledger", "ledger.json", "ledger file from the indexer")
	pool := fs.String("pool", "", "pool account address (32 bytes hex)")
	auditPK := fs.String("audit-pk", "", "audit key file")
	spend := fs.String("spend", "", "leaf indexes to spend, one or two, comma-separated")
	to := fs.String("to", "", "recipient address")
	value := fs.Uint64("value", 0, "amount to pay; the rest is change to the wallet")
	out := fs.String("out", "transfer.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w, err := loadWallet(*wallet)
	if err != nil {
		return err
	}
	l, err := loadLedger(*ledger)
	if err != nil {
		return err
	}
	poolAddr, err := parse32(*pool)
	if err != nil {
		return fmt.Errorf("-pool: %w", err)
	}
	apk, err := loadAuditPK(*auditPK)
	if err != nil {
		return err
	}
	toAddr, err := decodeAddress(*to)
	if err != nil {
		return err
	}
	owned := w.Scan(l)
	var spends []client.Owned
	var in uint64
	seen := map[uint64]bool{}
	for _, s := range strings.Split(*spend, ",") {
		i, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return fmt.Errorf("-spend: %w", err)
		}
		if seen[i] {
			return fmt.Errorf("-spend: leaf %d given twice", i)
		}
		seen[i] = true
		found := false
		for _, o := range owned {
			if o.Index == i {
				spends = append(spends, o)
				in += o.Note.Value
				found = true
			}
		}
		if !found {
			return fmt.Errorf("leaf %d is not an unspent note of this wallet", i)
		}
	}
	if *value > in {
		return fmt.Errorf("paying %d from %d", *value, in)
	}
	var d note.Diversifier
	if _, err := rand.Read(d[:]); err != nil {
		return err
	}
	change, err := w.Address(d)
	if err != nil {
		return err
	}
	p, err := loadProver(*keys, "transfer")
	if err != nil {
		return err
	}
	tr, err := w.Pay(rand.Reader, l, poolAddr, &apk, spends,
		[2]client.Payment{{To: toAddr, Value: *value}, {To: change, Value: in - *value}})
	if err != nil {
		return err
	}
	pj, err := proofOf(p, tr.Circuit)
	if err != nil {
		return err
	}
	st := tr.Statement
	j := transferJSON{
		proofJSON: pj,
		Root:      note.Hex32(&st.Root),
		AuditHash: note.Hex32(&st.AuditHash),
		EncHash:   note.Hex32(&st.EncHash),
		SigHash:   note.Hex32(&st.SigHash),
		AuditBlob: hexBytes(st.AuditBlob),
	}
	for i := range st.Nullifiers {
		j.Nullifiers = append(j.Nullifiers, note.Hex32(&st.Nullifiers[i]))
	}
	for i := range st.Commitments {
		j.Commitments = append(j.Commitments, note.Hex32(&st.Commitments[i]))
		j.EncBlobs = append(j.EncBlobs, hexBytes(tr.EncBlobs[i]))
		j.Outputs = append(j.Outputs, tr.Outputs[i].ToOpening())
	}
	return writeJSON(*out, j)
}

type unshieldJSON struct {
	proofJSON
	Root        string `json:"root"`
	Nullifier   string `json:"nullifier"`
	Value       uint64 `json:"value"`
	Forced      bool   `json:"forced"`
	SigHash     string `json:"sighash"`
	Destination string `json:"destination"`
}

func unshieldCmd(args []string) error {
	fs := flag.NewFlagSet("unshield", flag.ExitOnError)
	keys := fs.String("keys", "keys", "keys directory")
	wallet := fs.String("wallet", "", "wallet file")
	ledger := fs.String("ledger", "ledger.json", "ledger file from the indexer")
	pool := fs.String("pool", "", "pool account address (32 bytes hex)")
	destination := fs.String("destination", "", "destination token account (32 bytes hex)")
	index := fs.Uint64("index", 0, "leaf index of the note to unshield")
	out := fs.String("out", "unshield.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w, err := loadWallet(*wallet)
	if err != nil {
		return err
	}
	l, err := loadLedger(*ledger)
	if err != nil {
		return err
	}
	poolAddr, err := parse32(*pool)
	if err != nil {
		return fmt.Errorf("-pool: %w", err)
	}
	dest, err := parse32(*destination)
	if err != nil {
		return fmt.Errorf("-destination: %w", err)
	}
	var owned *client.Owned
	for _, o := range w.Scan(l) {
		if o.Index == *index {
			o := o
			owned = &o
		}
	}
	if owned == nil {
		return fmt.Errorf("leaf %d is not an unspent note of this wallet", *index)
	}
	p, err := loadProver(*keys, "burn")
	if err != nil {
		return err
	}
	c, err := w.Unshield(l, poolAddr, dest, *owned)
	if err != nil {
		return err
	}
	pj, err := proofOf(p, c)
	if err != nil {
		return err
	}
	nf := w.Nullifier(*owned)
	sh := burn.SigHash(poolAddr, dest, nf, owned.Note.Value)
	return writeJSON(*out, unshieldJSON{
		proofJSON:   pj,
		Root:        note.Hex32(ptr(l.Root())),
		Nullifier:   note.Hex32(&nf),
		Value:       owned.Note.Value,
		Forced:      false,
		SigHash:     note.Hex32(&sh),
		Destination: note.HexBytes32(&dest),
	})
}

// writeSecretJSON is writeJSON for key material: owner-readable only.
func writeSecretJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes, mode 0600)\n", path, len(data))
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
