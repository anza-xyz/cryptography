# curve25519 (curve25519-sol)

**A pure-Rust implementation of group operations on Ristretto and Curve25519, forked from
[curve25519-dalek] with HEEA scalar decomposition and a reduced backend set.**

> For the original curve25519-dalek documentation see [README_dalek.md](README_dalek.md).

This crate is part of the [curve25519-sol](../README.md) workspace.

---

## Changes from curve25519-dalek

### HEEA Scalar Decomposition

A new `HEEADecomposition` trait and implementation have been added in:

- [`src/scalar/heea.rs`](src/scalar/heea.rs) – `curve25519_heea_vartime`, the core
  half-extended Euclidean algorithm
- [`src/traits.rs`](src/traits.rs) – `HEEADecomposition` trait (`heea_decompose`)
- [`src/backend/serial/scalar_mul/vartime_triple_base.rs`](src/backend/serial/scalar_mul/vartime_triple_base.rs) –
  `mul_128_128_256`, a four-variable MSM optimised for two 128-bit and one 256-bit scalar

Given a 256-bit hash scalar `h`, `heea_decompose` returns `(ρ, τ, flip_h)` such that:

```text
ρ ≡ ±τ·h  (mod ℓ)     // ρ and τ are both ≤ 128 bits
```

This allows verification of `sB = R + hA` to be rewritten as a 4-point MSM over ~128-bit
scalars, reducing the number of point doublings required and yielding roughly **~15% faster**
verification in practice.

See the [TCHES 2025 paper] for the full algorithm description.

### Reduced Backends

Only the following backends are maintained in this fork:

| Backend | Selection | Notes |
|---|---|---|
| `serial` | Automatic fallback | Pure Rust, 64-bit word size on 64-bit targets |
| `simd` / AVX2 | Runtime on x86-64 | Vectorised 4-wide field arithmetic |
| CUDA | Opt-in (`curve25519-cuda` crate) | GPU MSM via SPPARK/BLST |

The `fiat` (formally-verified fiat-crypto) and `unstable_avx512` backends present in upstream
have been removed.

---

## Use

```toml
curve25519-sol = { git = "https://github.com/zz-sol/ed25519-sol" }
```

### HEEA decomposition example

```rust,ignore
use curve25519::traits::HEEADecomposition;
use curve25519::scalar::Scalar;
use sha2::{Sha512, Digest};

// h is a typical 256-bit hash scalar
let h = Scalar::from_hash(Sha512::new().chain_update(b"some message"));

// Decompose into two ~128-bit scalars
let (rho, tau, flip_h) = h.heea_decompose();
// rho ≡ ±tau·h  (mod ℓ)
```

---

## Feature Flags

The feature flags are inherited from upstream with no additions:

| Feature | Default? | Description |
|---|:---:|---|
| `alloc` | ✓ | Multiscalar multiplication, batch inversion, batch compress. |
| `zeroize` | ✓ | `Zeroize` for all scalar and point types. |
| `precomputed-tables` | ✓ | Precomputed basepoint tables (~400 KB, ~4× faster basepoint mul). |
| `rand_core` | | `Scalar::random`, `RistrettoPoint::random`. |
| `digest` | | Hash-to-curve and `Scalar::from_hash`. |
| `serde` | | Serialization for all point and scalar types. |
| `legacy_compatibility` | | `Scalar::from_bits` (broken arithmetic, use only if required). |
| `group` | | `group` and `ff` crate trait impls. |
| `group-bits` | | `ff::PrimeFieldBits` for `Scalar`. |
| `lizard` | | Bytestring-to-Ristretto-point injection. |

---

## Backends

### Serial (default)

Pure-Rust, available on all targets.  64-bit arithmetic on 64-bit platforms.

### AVX2 (automatic on x86-64)

Runtime CPU-feature detection via `cpufeatures`.  4-wide vectorised field elements in
radix-25.5 representation.  Automatically selected when the CPU supports AVX2; falls through to
`serial` otherwise.

To hard-code AVX2 at compile time:

```sh
RUSTFLAGS='-C target-feature=+avx2' cargo build --release
```

### CUDA (opt-in)

See the [`curve25519-cuda`](../curve25519-cuda) crate.  Provides GPU-accelerated
multi-scalar multiplication using the [SPPARK] library.

---

## Safety

All point types enforce validity invariants at the type level (no invalid `EdwardsPoint` can be
constructed).  All secret-operand operations use constant-time logic via the [`subtle`] crate.
Variable-time functions are explicitly marked `vartime`.

The SIMD backend uses `unsafe` internally for SIMD intrinsics, guarded by runtime CPU-feature
checks.

---

## MSRV

Rust **1.85.0** (Edition 2024).

---

## References

- [TCHES 2025 paper] – _Accelerating EdDSA Signature Verification with Faster Scalar Size Halving_
- [curve25519-dalek] – upstream library (isis lovecruft, Henry de Valence)
- [Original curve25519-dalek README](README_dalek.md)

[TCHES 2025 paper]: https://tches.iacr.org/index.php/TCHES/article/view/11971
[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[SPPARK]: https://github.com/supranational/sppark
[subtle]: https://docs.rs/subtle
