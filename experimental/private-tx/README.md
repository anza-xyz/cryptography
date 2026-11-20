# Private transactions

Per-institution shielded pools on Solana: Groth16 over BN254, Poseidon
commitments, gnark circuits, verified on-chain by the generic
[Groth16 verifier program](https://github.com/solana-program/groth16-verifier-program).
Tracker: [anza-xyz/cryptography#123](https://github.com/anza-xyz/cryptography/issues/123).

Status: the framework (Go module, Poseidon library choice, fixture
tooling, Rust end-to-end harness against the verifier program, CI) and the
protocol's primitives: the key hierarchy, notes with their commitment and
nullifier, the commitment tree, and note encryption to the recipient and
to the custodian's audit key. Circuits are added on top of them.

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
| `circuits/export/` | writes gnark's native `vk.bin` / `proof.bin` / `public.bin` |
| `circuits/cmd/privtx/` | `privtx <circuit>-fixture`: setup, prove, export |
| `fixtures/<circuit>/` | a key, proof and public witness per circuit, consumed by `e2e/` |
| `e2e/` | Rust crate (its own workspace, not a member of the repository root): fixture → on-chain format → verifier host path and SBF program |

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
  custodian able to audit and forfeit.
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

The circuits that create notes compute the ciphertext in-circuit from the
very notes they commit to and publish `audit_hash`; the pool program
recomputes it from the blob in the instruction and the pool's audit key.
So the custodian can read every note's full opening, which forfeiture
needs, and a sender cannot put anything else there. Recipient blobs are
bound too: their hash `enc_hash = Poseidon(ENCH, 31-byte chunks)` enters
the circuits' public statement (`extra` above), so a transaction cannot
be altered in flight.

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
in its tests. The pool program will keep the same tree on-chain, so the
node hash is one `sol_poseidon` call.

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
make test-go        # Go: Poseidon vectors, gadget == native, keys and notes, Merkle tree, encryption, circuit prove/verify
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

