# curve25519-sol

A high-performance, opinionated fork of [curve25519-dalek] and [ed25519-zebra] focused on
accelerated Ed25519 signature verification via the **HEEA** (Half-Extended Euclidean Algorithm)
method and a reduced set of well-tested backends.

> Original library READMEs: [README_dalek.md](README_dalek.md) (workspace) ·
> [curve25519/README_dalek.md](curve25519/README_dalek.md) ·
> [ed25519-heea/README_zebra.md](ed25519-heea/README_zebra.md)

---

## Crates

| Crate | Description |
|---|---|
| [`curve25519`](./curve25519) | Fork of `curve25519-dalek`. Core elliptic-curve arithmetic over Curve25519, Edwards, Ristretto, and Short-Weierstrass forms, with HEEA scalar decomposition and a narrowed backend set. |
| [`ed25519-heea`](./ed25519-heea) | Fork of `ed25519-zebra`. ZIP-215-compliant Ed25519 with an added `verify_heea` fast-path that uses HEEA half-size scalars. |
| [`curve25519-cuda`](./curve25519-cuda) | GPU-accelerated multi-scalar multiplication (MSM) via CUDA/SPPARK. Falls back to CPU when CUDA is unavailable. |
| [`curve25519-derive`](./curve25519-derive) | Helper proc-macro crate (`#[unsafe_target_feature]`) inherited from upstream; required to write clean SIMD code. |

---

## Key Changes from Upstream

### HEEA Signature Verification

Standard Ed25519 verification checks **sB = R + hA**, where `h` is a 256-bit scalar.
HEEA (from the TCHES 2025 paper _"Accelerating EdDSA Signature Verification with Faster Scalar
Size Halving"_) transforms this into a 4-point MSM with ~128-bit scalars:

```
τs_lo · B + τs_hi · (2¹²⁸·B) = τ·R + ρ·A
```

where `ρ` and `τ` are half-size (~127-bit) values derived from `h` via a half-extended
Euclidean algorithm, and `τs = τs_hi · 2¹²⁸ + τs_lo`.  All four scalars are ≤128 bits, and
two of the bases (`B` and `2¹²⁸B`) use precomputed tables.  In practice this yields roughly
**~15% faster** verification compared to the standard double-scalar-multiplication path.

The algorithm is implemented in:
- [`curve25519/src/scalar/heea.rs`](curve25519/src/scalar/heea.rs) – `curve25519_heea_vartime`
- [`curve25519/src/traits.rs`](curve25519/src/traits.rs) – `HEEADecomposition` trait
- [`curve25519/src/backend/serial/scalar_mul/vartime_triple_base.rs`](curve25519/src/backend/serial/scalar_mul/vartime_triple_base.rs) – optimised 128+128+256 MSM
- [`ed25519-heea/src/verification_key.rs`](ed25519-heea/src/verification_key.rs) – `VerificationKey::verify_heea`

### Reduced Backend Set

Upstream `curve25519-dalek` supports serial, fiat-crypto, AVX2, and unstable AVX512 backends.
This fork retains only the backends actively tested and maintained here:

| Backend | Platform | Selection |
|---|---|---|
| `serial` | All (macOS, Linux, …) | Automatic fallback |
| `simd` / AVX2 | x86-64 with AVX2 | Runtime CPU detection |
| CUDA (separate crate) | NVIDIA GPU | Opt-in via `curve25519-cuda` |

The `fiat` (formally-verified) and `unstable_avx512` backends have been removed to reduce
maintenance surface. If you need them, use upstream `curve25519-dalek` directly.

---

## Usage

Add the relevant crate to `Cargo.toml`:

```toml
# Core curve arithmetic with HEEA
curve25519-sol = { git = "https://github.com/zz-sol/ed25519-sol" }

# Ed25519 signatures with fast HEEA verification
ed25519-heea = { git = "https://github.com/zz-sol/ed25519-sol" }
```

### Standard Ed25519 verification

```rust
use ed25519_heea::{SigningKey, VerificationKey};
use rand::thread_rng;

let msg = b"hello world";
let sk = SigningKey::new(thread_rng());
let sig = sk.sign(msg);
let vk = VerificationKey::from(&sk);

// Standard ZIP-215-compliant verification
vk.verify(&sig, msg).expect("valid signature");
```

### HEEA-accelerated verification

```rust
// Fast path: ~15% faster via half-size scalars (same result)
vk.verify_heea(&sig, msg).expect("valid signature");
```

---

## Building

```sh
# Standard build
cargo build --release

# With AVX2 (automatic on x86-64 at runtime; or force compile-time)
RUSTFLAGS='-C target-feature=+avx2' cargo build --release

# Run benchmarks
cargo bench --features "rand_core" -p curve25519
cargo bench -p ed25519-heea
```

---

## References

- [Accelerating EdDSA Signature Verification with Faster Scalar Size Halving](https://tches.iacr.org/index.php/TCHES/article/view/11971) — TCHES 2025
- [ZIP 215](https://zips.z.cash/zip-0215) — Ed25519 validation rules used by Zcash
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) — upstream curve library
- [ed25519-zebra](https://github.com/ZcashFoundation/ed25519-zebra) — upstream signature library

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Portions of this library are derived from [curve25519-dalek] (isis lovecruft, Henry de Valence)
and [ed25519-zebra] (Zcash Foundation), both dual-licensed MIT/Apache-2.0.

[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[ed25519-zebra]: https://github.com/ZcashFoundation/ed25519-zebra
