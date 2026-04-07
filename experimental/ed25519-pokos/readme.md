# Ed25519 Proof of Knowledge of Seed (POKOS)

This crate implements a zero-knowledge proof that the prover knows a seed used
to derive an Ed25519 secret key — without revealing the seed or the key.

The goal is not simply to prove knowledge of an Ed25519 secret key.  The seed,
or a commitment to it, is intended to be reused in a separate protocol that
derives post-quantum keys from the same root.  Because of that, the proof must
say something about the seed derivation path, not only about the final Ed25519
key material.

## Protocol shape

The public statement is `(commit_of_seed, hash_of_sk)`.  The prover holds the
secret `seed` and proves the following derivation chain in zero knowledge:

```
commit_of_seed = SHA512("ed25519-pokos/commit/v1"   || seed)
prf_output     = SHA512("ed25519-pokos/derive-sk/v1" || seed)
sk_seed        = prf_output[0..32]
hash_of_sk     = SHA512("ed25519-pokos/hash-sk/v1"  || sk_seed)
```

Each domain label is zero-padded to 32 bytes, then concatenated with the
32-byte payload to form a single 64-byte message hashed in one SHA-512 block.

All three SHA-512 evaluations are proved by a single Plonky3 STARK over the
SHA-512 compression function.  The outer proof envelope is then signed by the
Ed25519 key derived from `sk_seed`, binding the proof to the key owner without
exposing either the seed or the secret key.

## Security tradeoff

This is a **temporary** construction.  It does not prove `sk → pk` inside the
circuit; that link is enforced externally by the Ed25519 signature over the
proof transcript.

- The ZK proof ties `seed → sk`.
- The Ed25519 signature ties `sk → pk`.

This is weaker than a fully end-to-end statement because the linkage to `pk` is
not proven inside the circuit — it is enforced by an external signature.

In the pre-quantum setting this is sufficient: only the legitimate owner of `sk`
can produce a valid signature.  In a post-quantum setting, once an adversary can
recover `sk` from `pk`, the signature no longer adds meaningful security.  At
that point the temporary authentication layer becomes unnecessary anyway, and the
system can rely on the revealed `sk` directly.

This construction should be read as a temporary engineering compromise, not as
the ideal final statement.

## Fully sound version

The fully sound end-to-end statement would use these public inputs:
- `commit_of_seed`
- `pk`

And prove:
- `commit_of_seed` commits to some seed
- the seed is transformed into the Ed25519 secret key `sk` by the specified PRF
- the corresponding Ed25519 public key derived from `sk` is exactly `pk`

This directly binds the seed commitment to the Ed25519 public key inside the
proof, with no external signature required.

## Why the fully sound version is not used here

The main bottleneck is proving Ed25519 group operations inside the circuit under
emulated arithmetic.  Our proof-of-concept for the fully end-to-end version
exceeds **1 billion gates**.  The dominant cost is in-circuit elliptic-curve
arithmetic for the `sk → pk` derivation.

By contrast, this construction avoids that expensive step: instead of proving
`sk → pk` in circuit it exposes `hash_of_sk` and delegates the `sk → pk` link
to an external Ed25519 signature.  The result is far more practical:

| Construction | Proof size (default settings) |
|---|---|
| This crate (temporary) | ~401 KB |
| Fully end-to-end | not yet practical |

## Crate layout

```
src/
  lib.rs               — public types, constants, and re-exports
  prover.rs            — key derivation, statement assembly, proof generation
  verifier.rs          — STARK verification, Ed25519 auth check, serialization
  private_seed_chain.rs — public witness/layout types for the three-segment chain
  sha512/              — Plonky3 AIR, trace builder, constraints, proof API
    air.rs             — Sha512RoundAir (implements the Plonky3 Air trait)
    circuit.rs         — Sha512Circuit: reference hash, block compression, trace gen
    private_seed_chain.rs — STARK prover/verifier for the seed chain
    proof_api/         — STARK config, FRI settings, serialization
```

The `prover` and `verifier` modules are intentionally separated so that a
verifier binary need not link any prover code.

## Wire format

`serialize_proof` / `deserialize_proof` produce a versioned byte sequence:

```
[magic: 8 bytes "EPKOS001"]
[commit_of_seed: 64 bytes]
[hash_of_sk: 64 bytes]
[sha512_proof_len: 8 bytes big-endian u64] [sha512_proof: N bytes]
[authentication_key: 32 bytes]
[authentication_signature: 64 bytes]
```

## Usage

```rust
use ed25519_pokos::{Seed, gen_pokos, verify_pokos, serialize_proof, deserialize_proof};

// ── Prover ──────────────────────────────────────────────────────────────────
let seed: Seed = [7_u8; 32];
let proof = gen_pokos(seed)?;

// Inspect the public statement without running the verifier:
println!("commit_of_seed: {:02x?}", proof.statement.commit_of_seed);
println!("hash_of_sk:     {:02x?}", proof.statement.hash_of_sk);

// Serialize for transport:
let proof_bytes = serialize_proof(&proof);

// ── Verifier (can run in a separate process / binary) ─────────────────────
let proof = deserialize_proof(&proof_bytes)?;
verify_pokos(&proof)?;
# Ok::<(), String>(())
```

Run the bundled example:

```bash
cargo run --release -p ed25519-pokos --example gen_verify_pokos
```

Sample output (fixed seed `[7u8; 32]`, timings vary by machine):

```
commit_of_seed: [01, ff, 79, 8a, 05, 6f, b4, a4, 25, 13, 16, d5, 9e, a3, fe, 21, e9, 1e, 56, dd, 6b, cb, 69, db, 03, dd, 27, f2, 06, 8d, 9a, a2, ca, c0, cc, f2, 6f, d3, 9f, 4c, cb, ac, 00, 8a, d8, c1, c0, 70, f8, 51, d2, c4, 64, b0, e7, bb, de, 4f, 86, bb, 0e, 2f, e1, dc]
hash_of_sk: [52, 5c, 52, 0a, 8a, 61, bf, 28, df, 5b, a5, 4e, 31, fe, 53, 2d, 43, 3a, 35, 91, 5d, 6e, 78, 71, 4f, 01, 4c, de, c7, d8, 5f, 48, 9e, 91, a4, 3a, c9, be, 1b, ce, 63, a1, 15, 79, 84, 14, b4, ef, 06, c6, ec, c9, 60, 78, 0a, 52, 0c, ff, 48, d8, 75, fd, 6a, 67]
proving_time_ms: 55
verification_time_ms: 13
air_trace_rows: 512
air_trace_cols: 1076
proof_bytes: 400848
verification: ok
```

The trace shape and proof envelope bytes are stable unless the AIR or the
default `Sha512ProofSettings` change.

## Current implementation status

- The STARK proves all three SHA-512 relations in a single concatenated
  three-segment proof.
- The authentication key and signature use the Ed25519 implementation in this
  repo (`curve25519` crate).
- The `sk → pk` link is **not** proved inside the circuit; it remains external
  and is enforced by the Ed25519 signature over the proof statement.
- The proof settings (`Sha512ProofSettings`) are configurable, but the
  verifier enforces minimum security thresholds and rejects proofs produced
  with weaker parameters.
