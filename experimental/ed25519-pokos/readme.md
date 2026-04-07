# Ed25519 Proof of Knowledge of Seed

This crate documents a temporary proof construction for showing knowledge of a seed that is used
to derive an Ed25519 secret key.

The goal is not just to prove knowledge of an Ed25519 secret key. The seed, or a commitment to the
seed, is intended to be reused later in a separate protocol that derives post-quantum keys. Because
of that, the proof needs to say something about the seed derivation path, not only about the final
Ed25519 key material.

## What This Repo Implements

This repo implements a **less sound but practical** construction.

Public inputs:
- `commit_of_seed`
- `hash_of_sk`

Statements:
- `commit_of_seed` is a commitment to some seed
- the seed is transformed into the Ed25519 secret key `sk` by the specified PRF / derivation logic
- `hash_of_sk` is the hash of that `sk`

The intended use is:
- `commit_of_seed` or the seed itself is later reused in a separate protocol to derive PQ keys
- the proof shows that the same hidden seed was used to derive an Ed25519 secret key
- the proof does **not** itself show that this secret key corresponds to a specific public key `pk`

Because the proof does not bind the seed to `pk`, the current workaround is to authenticate the
proof externally with Ed25519 itself: the owner of `sk` signs the proof, or the proof transcript,
using the corresponding `pk`.

That gives a practical binding today:
- the ZK proof ties `seed -> sk`
- the Ed25519 signature ties `sk -> pk`

This is weaker than a fully end-to-end statement because the linkage to `pk` is not proven inside
the circuit. It is instead enforced by an external signature.

## Security Tradeoff

The tradeoff is explicit:

- Today, this construction is usable because the legitimate owner of `sk` can authenticate the
  proof with an Ed25519 signature.
- In a post-quantum setting, once an adversary can recover `sk` from `pk`, that signature no longer
  adds meaningful security.
- At that point the temporary authentication layer becomes unnecessary anyway, because the secret
  key is effectively exposed and the system can rely on the revealed `sk` directly.

So this construction should be read as a temporary engineering compromise, not as the ideal final
statement.

## Fully Sound Version

The fully sound end-to-end statement would use these public inputs:
- `commit_of_seed`
- `pk`

Statements:
- `commit_of_seed` is a commitment to some seed
- the seed is transformed into the Ed25519 secret key `sk` by the specified PRF / derivation logic
- the corresponding Ed25519 public key derived from `sk` is exactly `pk`

This is the clean statement we ultimately want, because it proves the entire chain inside the proof:

`seed -> sk -> pk`

That version directly binds the seed commitment to the Ed25519 public key, with no need for an
external signature.

## Why We Do Not Use the Fully Sound Version Here

The main bottleneck is proving Ed25519 group operations inside the circuit with emulated
arithmetic. In the current proof system, that cost is too high for the intended deployment shape.

Our proof-of-concept for the fully end-to-end version already exceeds **1 billion gates**. The
dominant cost is the in-circuit elliptic-curve arithmetic needed to derive and verify the Ed25519
public key relation.

By contrast, the temporary construction in this repo avoids proving the expensive group relation in
the circuit. Instead of exposing `pk` as a public input and proving `sk -> pk`, it exposes only
`hash_of_sk` and moves the `sk -> pk` linkage to an external Ed25519 signature.

This increases proof size relative to the smallest Plonky3 setting, but it is still far more
practical than the full end-to-end circuit. On the current implementation and default settings,
the runnable release example produces a proof of about `401 KB`:

- temporary construction: about `401 KB` proof size in the current release example
- smallest Plonky3 target: still materially smaller in principle
- fully end-to-end construction: currently too large to be practical because of the circuit size

## Summary

This repo implements the pragmatic version:

- prove `commit_of_seed -> seed -> sk`
- publish `hash_of_sk`
- authenticate the proof with the Ed25519 key owner externally

It does **not** implement the strongest possible statement. The stronger construction would also
prove `sk -> pk` inside the circuit, but today that path is too expensive because Ed25519 group
operations under emulated arithmetic dominate the circuit size.

## Example

Generate and verify a proof:

```rust
use ed25519_pokos::{Seed, gen_pokos, verify_pokos};

let seed: Seed = [7_u8; 32];
let proof = gen_pokos(seed)?;
verify_pokos(&proof)?;
# Ok::<(), String>(())
```

Run the runnable example:

```bash
cargo run --release -p ed25519-pokos --example gen_verify_pokos
```

Sample output from a local release run:

```text
commit_of_seed: [01, ff, 79, 8a, 05, 6f, b4, a4, 25, 13, 16, d5, 9e, a3, fe, 21, e9, 1e, 56, dd, 6b, cb, 69, db, 03, dd, 27, f2, 06, 8d, 9a, a2, ca, c0, cc, f2, 6f, d3, 9f, 4c, cb, ac, 00, 8a, d8, c1, c0, 70, f8, 51, d2, c4, 64, b0, e7, bb, de, 4f, 86, bb, 0e, 2f, e1, dc]
hash_of_sk: [52, 5c, 52, 0a, 8a, 61, bf, 28, df, 5b, a5, 4e, 31, fe, 53, 2d, 43, 3a, 35, 91, 5d, 6e, 78, 71, 4f, 01, 4c, de, c7, d8, 5f, 48, 9e, 91, a4, 3a, c9, be, 1b, ce, 63, a1, 15, 79, 84, 14, b4, ef, 06, c6, ec, c9, 60, 78, 0a, 52, 0c, ff, 48, d8, 75, fd, 6a, 67]
proving_time_ms: 55
verification_time_ms: 13
air_trace_rows: 512
air_trace_cols: 1076
proof_bytes: 401088
verification: ok
```

That example uses the fixed demo seed `[7_u8; 32]`. The exact timings will vary by machine, but
the trace shape and proof envelope structure are expected to remain stable unless the AIR or proof
settings change.

## Current Implementation Status

The current crate implements the temporary construction with **one real SHA-512 circuit proof**
plus an external Ed25519 authentication step.

- `commit_of_seed` is a domain-separated SHA-512 hash of the seed
- `sk` is derived from the seed by a separate domain-separated SHA-512 step
- `hash_of_sk` is a domain-separated SHA-512 hash of the derived Ed25519 seed
- the three SHA-512 relations are grouped into a single concatenated proof implemented inside this
  crate
- the authentication key and signature use the local Ed25519 implementation in this repo
- the outer proof envelope has a versioned byte serialization format for transport between prover
  and verifier components
- the crate exposes separate `prover` and `verifier` modules so proof creation and proof checking
  can be consumed independently

The crate still does **not** prove the Ed25519 group relation `sk -> pk` inside the circuit. That
link remains external and is enforced by the Ed25519 signature over the proof statement.
