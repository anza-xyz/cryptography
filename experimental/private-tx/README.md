# Private transactions

Per-institution shielded pools on Solana: Groth16 over BN254, Poseidon
commitments, gnark circuits, verified on-chain by the generic
[Groth16 verifier program](https://github.com/solana-program/groth16-verifier-program).
Background: [goals.md](goals.md), [high_level_design.md](high_level_design.md),
tracker [anza-xyz/cryptography#123](https://github.com/anza-xyz/cryptography/issues/123).

Status: milestone 1. The framework (Go module, Poseidon library choice,
fixture tooling, Rust end-to-end harness against the verifier program, CI) is
in place and `C_mint` is implemented; its proof verifies through the verifier
program under Mollusk.

## Layout

| Path | What |
| --- | --- |
| `circuits/` | Go module (gnark): circuits, gadgets, fixture CLI |
| `circuits/poseidon/` | thin adapter over third-party circom-compatible Poseidon (native and gadget) |
| `circuits/smoke/` | trivial `A·B = C` circuit that exercises the pipeline end to end |
| `circuits/note/` | note format and commitment |
| `circuits/mint/` | `C_mint` |
| `circuits/export/` | writes gnark's native `vk.bin` / `proof.bin` / `public.bin` |
| `circuits/cmd/privtx/` | `privtx <circuit>-fixture`: setup, prove, export |
| `fixtures/<circuit>/` | a key, proof and public witness per circuit, consumed by `e2e/` |
| `e2e/` | Rust crate (workspace member): fixture → on-chain format → verifier host path and SBF program |

## Poseidon

All hashing is the circom Poseidon over BN254 Fr: `x^5` S-box, 8 full rounds,
width-dependent partial rounds, capacity element 0, digest `state[0]`. These
are the parameters of circomlib, light-poseidon, Solana's `sol_poseidon`
syscall and `syscall/solana-bn254` in this repository, so a pool program can
recompute any in-circuit hash with one syscall.

No Poseidon is implemented here. The circuits use two public libraries:

- in-circuit: `github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon`,
  a gnark port of circomlib's `poseidon.circom`;
- native (witness side): `github.com/iden3/go-iden3-crypto/poseidon`, the
  reference implementation by circom's authors.

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
- `rho`: per-note uniqueness, later the nullifier input.
- `r`: commitment randomness.

No asset field: the pool fixes the asset.

## C_mint

Issuance of one note with a public amount. The issuer proves the published
commitment opens to a well-formed note carrying exactly the published value,
so the pool program can account for minted supply (and match a vault deposit
for a wrapped asset, design §2.2) while the recipient stays hidden. Who may
mint is the pool program's business (issuer authority), not the circuit's.

| | |
| --- | --- |
| public inputs | `commitment`, `value` (in that order) |
| witness | `owner_pk`, `rho`, `r` |
| constraints | `value ∈ [0, 2^64)` by bit decomposition; `commitment = Poseidon(value, owner_pk, rho, r)` |
| size | 363 R1CS constraints |

A confidential-issuance variant (hidden amount, design §7) is the same circuit
with `Value` moved to the private witness.

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
make test-go        # Go: Poseidon vectors, gadget == native, C_mint prove/verify
make test-e2e       # Rust (release): host-path verification of the fixtures
make verifier-sbf   # clone + build the verifier program (needs cargo build-sbf)
make test-e2e       # now also verifies the proofs inside the SBF program
make fixtures       # regenerate fixtures (random setup: bytes change)
```

The e2e crate pins the verifier repository to one git revision (in the root
`Cargo.toml` workspace dependencies and the `Makefile`); the fixture encodings
are gnark's native `WriteTo` / `MarshalBinary` forms, which that revision's
`groth16-convert` parses. The Groth16 setup in `privtx` is for development
only.

CI (`.github/workflows/ci.yml`, job `private-tx`) runs the Go tests, builds
the verifier program at the pinned revision, and runs the e2e crate with the
SBF test enabled.

## Next

- `C_transfer`: Merkle gadget (Poseidon width 3), nullifiers, 2-in/2-out
  conservation, auditor ciphertexts (Baby Jubjub ElGamal gadget).
- `C_burn`.
- Key hierarchy and domain separation of the Poseidon uses in the spec.
- Pool program and client glue (Epic 4).
