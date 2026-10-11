# Private transactions

Per-institution shielded pools on Solana: Groth16 over BN254, Poseidon
commitments, gnark circuits, verified on-chain by the generic
[Groth16 verifier program](https://github.com/solana-program/groth16-verifier-program).
Tracker: [anza-xyz/cryptography#123](https://github.com/anza-xyz/cryptography/issues/123).

Status: milestone 1. The framework (Go module, Poseidon library choice,
fixture tooling, Rust end-to-end harness against the verifier program, CI) is
in place and `C_mint` and `C_burn` are implemented; their proofs verify
through the verifier program under Mollusk.

## Layout

| Path | What |
| --- | --- |
| `circuits/` | Go module (gnark): circuits, gadgets, fixture CLI |
| `circuits/poseidon/` | thin adapter over third-party circom-compatible Poseidon (native and gadget) |
| `circuits/smoke/` | trivial `A·B = C` circuit that exercises the pipeline end to end |
| `circuits/note/` | note format, commitment and nullifier |
| `circuits/merkle/` | commitment tree: native tree and membership gadget |
| `circuits/mint/` | `C_mint` |
| `circuits/burn/` | `C_burn` (owner unshield and custodian forfeiture) |
| `circuits/export/` | writes gnark's native `vk.bin` / `proof.bin` / `public.bin` |
| `circuits/cmd/privtx/` | `privtx <circuit>-fixture`: setup, prove, export |
| `fixtures/<circuit>/` | a key, proof and public witness per circuit, consumed by `e2e/` |
| `e2e/` | Rust crate (its own workspace, not a member of the repository root): fixture → on-chain format → verifier host path and SBF program |

## Poseidon

All hashing is the circom Poseidon over BN254 Fr: `x^5` S-box, 8 full rounds,
width-dependent partial rounds, capacity element 0, digest `state[0]`. These
are the parameters of circomlib, light-poseidon, Solana's `sol_poseidon`
syscall and `syscall/solana-bn254` in this repository, so a pool program can
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
`syscall/solana-bn254` generates its constants from) for circuits to check
their in-circuit hashes against.

## Note

```
note = (value, owner_pk, rho, r)
cm   = Poseidon(value, owner_pk, rho, r)        // width 5
```

- `value`: `u64`.
- `owner_pk`: the recipient's key as an opaque field element. The key
  hierarchy is spec work (Epic 1); fixtures use the provisional
  `owner_pk = Poseidon(sk)`.
- `rho`: per-note uniqueness, the nullifier input.
- `r`: commitment randomness.

No asset field: the pool fixes the asset.

Spending or forfeiting a note publishes its nullifier

```
nf = Poseidon(owner_pk, rho)                   // width 3
```

This is Sapling's `PRF_nk(rho)` with the public key in place of the secret
nullifier key, so anyone holding the opening can derive it. That is what lets
the custodian, who learns openings through the audit ciphertexts, forfeit a
note without the owner's key (`C_burn` with `forced = 1`); the price is that whoever created the note can
recognize its nullifier when it is spent. The derivation is provisional (key
hierarchy, Epic 1) and lives in one place, `note.Nullifier` and
`note.NullifierGadget`, so every circuit that emits one changes together.

## Commitment tree

```
leaf          = commitment
node          = Poseidon(left, right)           // width 3
empty leaf    = 0, empty subtrees hashed up from it
depth         = 32                              // provisional, spec decides
```

Leaves are appended left to right; bit `i` of the leaf index picks the right
child at height `i`. `circuits/merkle/` has the native tree (witness side)
and the membership gadget, with the native path and the gadget cross-checked
in its tests; the e2e crate rebuilds the fixture tree with light-poseidon to
pin the gadget against the Solana syscall's Poseidon. The pool program keeps
the same tree on-chain.

## C_mint

Issuance of one note with a public amount. The issuer proves the published
commitment opens to a well-formed note carrying exactly the published value,
so the pool program can account for minted supply (and match a vault deposit
for a wrapped asset) while the recipient stays hidden. Who may mint is the
pool program's business (issuer authority), not the circuit's.

| | |
| --- | --- |
| public inputs | `commitment`, `value` (in that order) |
| witness | `owner_pk`, `rho`, `r` |
| constraints | `value ∈ [0, 2^64)` by bit decomposition; `commitment = Poseidon(value, owner_pk, rho, r)` |
| size | 363 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

A confidential-issuance variant (hidden amount) is the same circuit with
`Value` moved to the private witness.

The circuit touches neither Merkle tree. The commitment is a public input, so
the pool program appends it to the commitment tree itself after verifying the
proof; proving the insertion in-circuit would only repeat work the program
does in the clear. Membership in the tree is proved when a note is spent, by
`C_transfer` and `C_burn`. The nullifier set is untouched because a mint
spends nothing: `rho` is carried in the note so that a later spend can derive
the nullifier from it. The on-chain mint flow is therefore: verify the proof,
check issuer authority, add `value` to minted supply, append `commitment`.

## C_burn

Removal of one note from the pool with a public amount: the owner's unshield
and the custodian's forfeiture are the same relation, so they are one circuit
with a public flag saying which authorization applies. The prover shows the
note is in the commitment tree and publishes its nullifier and value; the
pool program records the nullifier, so the note cannot be spent again, and
releases the amount (vault withdrawal, supply decrease).

| | |
| --- | --- |
| public inputs | `root`, `nullifier`, `value`, `forced` (in that order) |
| witness | `owner_pk`, `rho`, `r`, `sk`, leaf index, 32 Merkle siblings |
| constraints | `forced ∈ {0, 1}`; `forced ∨ owner_pk = Poseidon(sk)`; `commitment = Poseidon(value, owner_pk, rho, r)`; `root = MerkleRoot(commitment, index, siblings)`; `nullifier = Poseidon(owner_pk, rho)` |
| size | 8532 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

- `forced = 0`, unshield: the proof shows knowledge of the owner's spending
  key, so it carries the owner's consent and the program accepts it from
  anyone.
- `forced = 1`, forfeiture: no ownership check, the "alternative
  nullifier-authorization path" the design left open. The custodian learns
  the opening from the audit ciphertext and removes the note without the
  owner's key. The program must require the custodian's signature whenever
  the flag is set; the circuit only tells it which case it is in.

No range check on `value`: it is bound to a leaf, and every leaf was
range-checked by the circuit that created it. The root is checked by the
program against its root history. `C_transfer`'s spend side is this relation
with `forced = 0`.

Two spec items this depends on: the audit ciphertext must carry the full
opening (`owner_pk`, `rho`, `r`), not only the value, for forfeiture to work;
and the statement should bind where the released amount goes, so a proof
cannot be replayed from the mempool with another recipient.

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
make test-go        # Go: Poseidon vectors, gadget == native, Merkle tree, C_mint / C_burn prove/verify
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

## Next

- `C_transfer`: spend side = `C_burn` with `forced = 0`; 2-in/2-out
  conservation, auditor ciphertexts (Baby Jubjub ElGamal gadget).
- Key hierarchy and domain separation of the Poseidon uses in the spec.
- Pool program and client glue (Epic 4).
