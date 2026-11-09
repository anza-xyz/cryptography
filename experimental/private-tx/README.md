# Private transactions

Per-institution shielded pools on Solana: Groth16 over BN254, Poseidon
commitments, gnark circuits, verified on-chain by the generic
[Groth16 verifier program](https://github.com/solana-program/groth16-verifier-program).
Tracker: [anza-xyz/cryptography#123](https://github.com/anza-xyz/cryptography/issues/123).

Status: `C_mint`, `C_transfer` and `C_burn` are implemented with note
encryption to recipients and to the custodian's audit key, and a Go client
builds their witnesses from a ledger and proves them. The mint and burn
fixtures it writes verify through the Groth16 verifier program, on the host
path and under Mollusk, with every in-circuit hash recomputed in Rust with
the Solana syscall's Poseidon and both ciphertexts decrypted. The pool
program is next.

## Layout

| Path | What |
| --- | --- |
| `circuits/` | Go module (gnark): circuits, gadgets, fixture CLI |
| `circuits/poseidon/` | thin adapter over third-party circom-compatible Poseidon (native and gadget) |
| `circuits/smoke/` | trivial `A·B = C` circuit that exercises the pipeline end to end |
| `circuits/note/` | key hierarchy, note format, commitment and nullifier |
| `circuits/merkle/` | commitment tree: native tree and membership gadget |
| `circuits/domain/` | Poseidon domain tags |
| `circuits/encrypt/` | note encryption to the recipient (off-circuit) and to the audit key (gadget + native) |
| `circuits/mint/` | `C_mint` |
| `circuits/transfer/` | `C_transfer` (2-in/2-out) |
| `circuits/burn/` | `C_burn` (owner unshield and custodian forfeiture) |
| `circuits/client/` | wallet side: ledger, scanning, witness building, proving |
| `circuits/export/` | writes gnark's native `vk.bin` / `proof.bin` / `public.bin` |
| `circuits/cmd/privtx/` | `privtx <circuit>-fixture`: setup, prove, export |
| `fixtures/<circuit>/` | a key, proof and public witness per circuit, with the opened witness as JSON, consumed by `e2e/` |
| `e2e/` | Rust crate (own workspace): fixture → on-chain format → verifier host path and SBF program; plus the embedded curve and note decryption (`curve`, `encrypt`) |

## Poseidon

All hashing is the circom Poseidon over BN254 Fr: `x^5` S-box, 8 full rounds,
width-dependent partial rounds, capacity element 0, digest `state[0]`. These
are the parameters of circomlib, light-poseidon, Solana's `sol_poseidon`
syscall and `syscall/bn254-backend` in this repository, so a pool program can
recompute any in-circuit hash with one syscall.

No Poseidon is implemented here. gnark's own `std/hash` ships MiMC and
Poseidon2 but not the original Poseidon with circomlib's parameters, which is
what the syscall computes, so the circuits use two public libraries instead:

- in-circuit: `github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon`,
  a gnark port of circomlib's `poseidon.circom`;
- native (witness side): `github.com/iden3/go-iden3-crypto/poseidon`, the
  reference implementation by circom's authors.

Both libraries absorb up to 16 inputs in one permutation; the adapter in
`circuits/poseidon/` caps hashes at the 12 inputs `sol_poseidon` supports, so
an on-chain program can always recompute them.

Compatibility is pinned by tests rather than assumed: the Go tests check both
against circomlib's published vectors and against each other on random inputs
for 1 to 5 inputs, and the Rust e2e crate exposes light-poseidon (the source
`syscall/bn254-backend` generates its constants from) for circuits to check
their in-circuit hashes against.

## Keys and notes

The key hierarchy is Sapling's with Poseidon for every hash and PRF, and
gnark-crypto's twisted Edwards curve over BN254 Fr as the embedded group
(Baby Jubjub in `a = -1` form: same prime-order subgroup, cofactor 8).

```
sk                                spending key, a field element
ask = KeyGen(Poseidon(ASK, sk))   spend authorizing key (EdDSA secret)
ak  = [ask]G                      spend authorizing public key
nk  = Poseidon(NK, sk)            nullifier key
fvk = (ak, nk)                    full viewing key
ivk = Poseidon(IVK, ak.x, ak.y, nk)    incoming viewing key, used as a scalar
g_d = GroupHash(d)                diversifier base, d an 11-byte diversifier
pk_d = [ivk]·g_d                  diversified transmission key
address = (d, pk_d)
```

- Spending needs `ask` (to sign) and `nk` (to derive the nullifier).
  Seeing a note, and forfeiting it through the custodian, needs `fvk` only.
  Institutions register their clients' `fvk`; that is what makes the
  custodian able to audit and forfeit (§C_burn).
- One key has as many addresses as diversifiers; without `ivk` two of them
  are unlinkable (`pk_d = [ivk]g_d` with independent bases).
- `GroupHash(d)`: `x = Poseidon(GD, d, counter)` for the first counter that
  gives a curve point, smaller `y`, cofactor cleared; at most 8 counters
  (a diversifier needing more is unusable, probability 2⁻⁸). The circuits
  that create notes replay it: the witness carries the counter, the point
  before cofactor clearing and, for every earlier counter, a square root
  of `5·rhs` (5 is a non-residue), which is what shows `rhs` was not a
  square; the hit's `y` is checked to be the smaller root, and
  `g_d = [8](x, y)`. Without this a self-shielder could commit to a base
  that is not `GroupHash(d)`: spendable by them (spending never uses `d`),
  unrecoverable from the audit ciphertext, so beyond forfeiture. `g_d` is
  also checked not to be of small order, so `pk_d = [ivk]g_d` binds `ivk`
  modulo the full subgroup order.

```
note = (value, d, pk_d, r)
cm   = Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r)     // width 8
nf   = Poseidon(NF, nk, cm, leaf index)                         // width 5
```

- `value`: `u64`. No asset field: the pool fixes the asset.
- `r`: commitment randomness.
- The nullifier takes the note's position, as Sapling's does (`rho = cm +
  [position]J` there): two notes with the same opening are different leaves
  with different nullifiers, so a sender cannot hand out notes that collide
  ("Faerie Gold"). Only the holder of `nk` can derive a nullifier, so a
  note's creator cannot tell when it is spent.

Every Poseidon call is domain-separated: its first input is a constant tag,
the ASCII of a short name (`privtx/cm`, `privtx/nf`, `privtx/nk`,
`privtx/ask`, `privtx/ivk`, `privtx/gd`, `privtx/node`, `privtx/sighash`,
`privtx/tsighash`, `privtx/kdf`, `privtx/enc`, `privtx/audit`,
`privtx/ench`) read as a big-endian integer. `circuits/domain/` lists them;
the pool program and the e2e crate spell the same strings.

## Note encryption

Every output note travels with two ciphertexts, Sapling's construction with
Poseidon in place of BLAKE2b and ChaCha20 (`circuits/encrypt/`).

To the recipient, off-circuit, 83 bytes:

```
esk random;  epk = [esk]·g_d;  ss = [esk]·pk_d = [ivk]·epk
key  = Poseidon(KDF, ss.x, ss.y, epk.x, epk.y);  ks_i = Poseidon(ENC, key, i)[1:32]
blob = epk (compressed, 32) ‖ (value LE 8 ‖ d 11 ‖ r 32) ⊕ (ks_0 ‖ ks_1)[0:51]
```

Each keystream element contributes its 31 low bytes: the top byte of a
canonical field element is biased (always below 0x31) and would leak two
bits of whatever it masked. A wallet trial-decrypts every blob with `ivk`, derives `pk_d` from `d`,
recommits, and keeps the notes whose commitment is the leaf's: that check
is the integrity check, as in Sapling, so there is no MAC. Nothing forces
a sender to encrypt honestly; a garbage blob costs them the payment.

To the custodian, inside the circuit, three field elements per note:

```
esk random, one per transaction;  epk = [esk]·G;  ss = [esk]·apk = [ask]·epk
key = Poseidon(KDF, ss.x, ss.y, epk.x, epk.y)
per note:  (packed, pk_d.y, r) + Poseidon(ENC, key, i),  packed = lsb(pk_d.x)·2^152 + value·2^88 + d
audit_hash = Poseidon(AUDIT, apk.x, apk.y, epk.x, epk.y, c_0, ..., extra...)
```

`C_mint` and `C_transfer` compute the ciphertext from the very notes they
commit to and publish `audit_hash`; the program recomputes it from the
blob in the instruction and the pool's audit key. So the custodian can
read every note's full opening, which forfeiture needs, and a sender
cannot put anything else there. Recipient blobs are bound too: their hash
`enc_hash = Poseidon(ENCH, 31-byte chunks)` enters the mint's `audit_hash`
and the transfer's sighash, so a transaction cannot be altered in flight.

## Commitment tree

```
leaf          = commitment
node          = Poseidon(NODE, left, right)     // width 4
empty leaf    = 0, empty subtrees hashed up from it
depth         = 32                              // provisional, spec decides
```

Leaves are appended left to right; bit `i` of the leaf index picks the right
child at height `i`. `circuits/merkle/` has the native tree (witness side)
and the membership gadget, with the native path and the gadget cross-checked
in its tests; the e2e crate rebuilds the fixture tree with light-poseidon to
pin the gadget against the Solana syscall's Poseidon. The pool program will
keep the same tree on-chain.

## C_mint

Issuance of one note with a public amount. The issuer proves the published
commitment opens to a well-formed note carrying exactly the published value,
so the pool program can account for minted supply (and match a vault deposit
for a wrapped asset) while the recipient stays hidden. Who may mint is the
pool program's business (issuer authority), not the circuit's.

| | |
| --- | --- |
| public inputs | `commitment`, `value`, `audit_hash` (in that order) |
| witness | `g_d`, `pk_d`, `r`, `d`, `apk`, `esk`, `enc_hash` |
| constraints | `value ∈ [0, 2^64)` by bit decomposition; `d < 2^88`; `g_d = GroupHash(d)`, not of small order; `pk_d` on the curve; `commitment = Poseidon(CM, value, g_d, pk_d, r)`; `audit_hash` over the note's audit ciphertext and `enc_hash` |
| size | 12587 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

A confidential-issuance variant (hidden amount) is the same circuit with
`Value` moved to the private witness. The point checks are Sapling's
Output checks: without them a note could be created whose owner relation
`pk_d = [ivk]g_d` binds only a few bits of `ivk`.

The circuit touches neither Merkle tree. The commitment is a public input, so
the pool program appends it to the commitment tree itself after verifying the
proof; proving the insertion in-circuit would only repeat work the program
does in the clear. Membership in the tree is proved when a note is spent, by
`C_transfer` and `C_burn`. The nullifier set is untouched because a mint
spends nothing. The on-chain mint flow is therefore: verify the proof,
check issuer authority, add `value` to minted supply, append `commitment`.

## C_transfer

An in-pool shielded transfer of fixed arity: two notes in, two out
(`circuits/transfer/`). Each input is `C_burn`'s spend relation (owner,
membership, nullifier, signature over the sighash); each output is
`C_mint`'s note relation; values are conserved exactly, with no fee or
public value. A zero-value input is a dummy, as in Sapling: its root check
is skipped (the note is in no tree) but it still carries a well-formed
owner, nullifier and signature, so every transaction has the same shape.

| | |
| --- | --- |
| public inputs | `root`, `nf_0`, `nf_1`, `cm_0`, `cm_1`, `audit_hash`, `sighash` (in that order) |
| witness | per input: `ak`, `nk`, `g_d`, `pk_d`, `r`, `value`, leaf index, 32 siblings, signature; per output: `g_d`, `pk_d`, `r`, `value`, `d`; `apk`, `esk` |
| constraints | per input: owner relation, `(root_i − root)·(1 − [value_i = 0]) = 0`, nullifier, `EdDSA.Verify(ak_i, sighash)`; per output: `value < 2^64`, `d < 2^88`, `g_d = GroupHash(d)`, point checks, commitment; `Σ in = Σ out`; `audit_hash` over both outputs |
| size | 59234 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

```
sighash = Poseidon(TSIGHASH, pool[0:16], pool[16:32], nf_0, nf_1, cm_0, cm_1, audit_hash, enc_hash)
```

Both owners sign it, so consent covers every byte of the transaction. The
circuit itself allows the same note as both inputs (equal nullifiers); the
program rejects that, as Zcash's consensus rules do.

## C_burn

Removal of one note from the pool with a public amount: the owner's unshield
and the custodian's forfeiture are the same relation, so they are one circuit
with a public flag saying which authorization applies. The prover shows the
note is in the commitment tree and publishes its nullifier and value; the
pool program records the nullifier, so the note cannot be spent again, and
releases the amount (vault withdrawal, supply decrease).

| | |
| --- | --- |
| public inputs | `root`, `nullifier`, `value`, `forced`, `sighash` (in that order) |
| witness | `ak`, `nk`, `g_d`, `pk_d`, `r`, signature `(R, S)`, leaf index, 32 Merkle siblings |
| constraints | `forced ∈ {0, 1}`; `ivk = Poseidon(IVK, ak, nk)`; `g_d` not of small order; `pk_d = [ivk]g_d`; `forced ∨ EdDSA.Verify(ak, sighash, (R, S))`; `cm = Poseidon(CM, value, g_d, pk_d, r)`; `root = MerkleRoot(cm, index, siblings)`; `nullifier = Poseidon(NF, nk, cm, index)` |
| size | 20919 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

The owner relation `pk_d = [ivk]g_d` is checked in both modes. It is what
ties `nk`, and so the published nullifier, to this note: a forfeiture with a
made-up `nk` would publish a nullifier that leaves the real one unspent,
and the note could be spent again after its value had been released. The
scalar multiplication is gnark's complete double-and-add, not its faster
lattice path, whose range checks are commitment-based under Groth16.

Authorization follows Zcash. Spending is a **spend authorization signature**
by the owner's key over a **sighash** of the transaction, not knowledge of a
secret inside the proof. The sighash is

```
sighash = Poseidon(SIGHASH, pool[0:16], pool[16:32], destination[0:16], destination[16:32], nullifier, value)
```

(Solana addresses are 256 bits, so each is two 128-bit halves.) The pool
program recomputes it from the instruction it is executing and passes it as
the last public input, so a proof is good for exactly one pool and one
destination: a copy fished out of the mempool with the recipient swapped
fails verification. Root and `forced` are public inputs of the same proof,
so the hash need not repeat them.

One deviation from Zcash: the signature is verified **inside the circuit**,
not on-chain. Zcash publishes a re-randomized key `rk` and checks the
signature in the transaction; Solana has no syscall for Baby Jubjub, so that
check would cost on the order of a million compute units in software, more
than ten proof verifications. In-circuit it costs about 7,800 constraints
(gnark's `std/signature/eddsa` with its MiMC challenge hash, which never
needs to match anything on-chain), and nothing about the key, not even a
re-randomization, is ever published. What Zcash's split buys is kept: the
prover needs the full viewing key and the signature, never `ask`, so proving
and signing can run on different machines (an HSM signs, a prover box
proves).
What is lost is proving before the transaction is final, since the sighash is
a public input.

- `forced = 0`, unshield: the proof carries the owner's signature over this
  transaction, so the program accepts it from anyone.
- `forced = 1`, forfeiture: no signature check, the "alternative
  nullifier-authorization path" the design left open. The custodian holds
  the owner's registered full viewing key and learns the opening from the
  audit ciphertext, and removes the note without `ask`; the witness carries
  a well-formed dummy signature the circuit ignores. The program must
  require the custodian's signature whenever the flag is set; the circuit
  only tells it which case it is in.

No range check on `value`: it is bound to a leaf, and every leaf was
range-checked by the circuit that created it. The root is checked by the
program against its root history. `C_transfer`'s spend side is this relation
with `forced = 0` and the output notes in place of `destination`.

Two spec items this depends on: the audit ciphertext must carry the full
opening (`d`, `pk_d`, `r`), not only the value, and clients must register
their full viewing keys with the custodian, for forfeiture to work.

## Client

`circuits/client/` is the wallet side in Go: a `Ledger` (leaves with their
recipient blobs, nullifiers seen) rebuilt from the chain, a `Wallet` that
scans it by trial decryption and builds shields, transfers (padding with a
dummy input, paying change as just another output) and unshields, a
`Forfeit` builder for the custodian, and a `Prover`. Its test runs a whole
lifecycle through it (shields, a transfer with change, an unshield and a
forfeiture) and proves every step. `privtx mint-fixture` and `privtx
burn-fixture` build their witnesses through it.

The Rust side of the same in `e2e/src/`: `curve` (the embedded curve,
compressed points, the group hash) and `encrypt` (recipient and audit
decryption, the hashes the program recomputes). Proving stays in Go.

The e2e tests `e2e/tests/mint.rs` and `e2e/tests/burn.rs` replay
`fixtures/mint/` and `fixtures/burn/`: they recompute the commitment, the
audit hash, the Merkle root, the nullifier and the sighash with
light-poseidon from the opened witness (`note.json`, `burn.json`), decrypt
the mint's recipient blob and audit ciphertext back to the note, check the
public-input order and that the keys are plain Groth16, and verify the
proofs on the host path and inside the verifier program, with tampered
public inputs rejected.

## Circuit rules

- Plain Groth16 only. No `std/rangecheck` or anything else built on
  `api.Commit`: under Groth16 those add commitment keys to the verifying key
  and a Pedersen commitment to the proof, which the on-chain verifier (and its
  `groth16-convert` parser) rejects. Range checks use `api.ToBinary`.
- Public inputs are in struct field order; document the order in the circuit
  package and assert it in the e2e test.
- Each circuit ships a fixture under `fixtures/<circuit>/` and an e2e test
  under `e2e/tests/` that verifies it on the host path and on the SBF program.

## Running

```bash
make lint           # gofmt + go vet; cargo fmt + clippy for e2e
make test-go        # Go: Poseidon vectors, gadget == native, keys and notes, Merkle tree, encryption, circuits, client lifecycle
make test-e2e       # Rust (release): host-path verification of the fixtures
make verifier-sbf   # clone + build the verifier program (needs cargo build-sbf 4.1+ for SBF v3; SBF_ARCH=v2 for older)
make test-e2e       # now also verifies the proofs inside the SBF program
make fixtures       # regenerate fixtures (random setup: bytes change)
```

The e2e crate is a standalone Cargo workspace: Mollusk brings in the SVM
runtime, which would otherwise bloat the root lockfile and every build in the
repository. It pins the verifier repository to one git revision (in
`e2e/Cargo.toml` and the `Makefile`); the fixture encodings
are gnark's native `WriteTo` / `MarshalBinary` forms, which that revision's
`groth16-convert` parses. The Groth16 setup in `privtx` is for development
only.

CI (`.github/workflows/private-tx.yml`, run only when this directory or the
workflow changes) lints and tests the Go side, builds the verifier program at
the pinned revision, regenerates the fixtures, and runs the e2e crate with the
SBF test enabled.

## Dependency pins

`vocdoni/gnark-crypto-primitives` v0.0.6 requires commits of gnark, gnark-crypto
and go-iden3-crypto that are newer than the releases it was built against, so
Go's minimum version selection carries those commits into `go.mod`. gnark and
gnark-crypto are raised to tagged releases that satisfy it; go-iden3-crypto has
no tag newer than the required commit, so it stays on that commit.

